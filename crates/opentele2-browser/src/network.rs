//! The Bayesian networks of the Apify fingerprint datapoints and their
//! sampler, a port of browserforge's `bayesian_network.py`.
//!
//! A network is a list of nodes in sampling order. Each node holds a
//! conditional probability table (CPT): a flat value-to-probability map when
//! the node has no parents, otherwise one `{"deeper": {parentValue: ...},
//! "skip": ...}` level per parent, in `parentNames` order. A parent value
//! missing from `deeper` descends into `skip`, or into an empty distribution
//! when there is none.
//!
//! The tree keeps the JSON key order, which fixes the order in which a draw
//! walks the candidates, and every string is interned once per network.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, OnceLock};

use serde::Deserialize;
use serde::de::{
    self, DeserializeSeed, IgnoredAny, IntoDeserializer, MapAccess, SeqAccess, Visitor,
};

use crate::rng::Rng;
use crate::{Error, Restrictions, Values};

/// The zipped input network: `*DEVICE`, `*OPERATING_SYSTEM`, `*BROWSER_HTTP`,
/// `*HTTP_VERSION`, `*BROWSER`.
pub const INPUT_NETWORK_ZIP: &[u8] = include_bytes!("../data/input-network-definition.zip");
/// The zipped HTTP header network.
pub const HEADER_NETWORK_ZIP: &[u8] = include_bytes!("../data/header-network-definition.zip");
/// The zipped browser fingerprint network.
pub const FINGERPRINT_NETWORK_ZIP: &[u8] =
    include_bytes!("../data/fingerprint-network-definition.zip");

/// An interned string of one network.
type Id = u32;

/// Above this many candidate-times-entry comparisons a restricted draw
/// indexes the distribution in a hash map instead of scanning it.
const LINEAR_LOOKUP_LIMIT: usize = 4096;

#[derive(Debug, Default)]
struct Interner {
    strings: Vec<Arc<str>>,
    ids: HashMap<Arc<str>, Id>,
}

impl Interner {
    fn intern(&mut self, value: &str) -> Option<Id> {
        if let Some(&id) = self.ids.get(value) {
            return Some(id);
        }
        let id = Id::try_from(self.strings.len()).ok()?;
        let shared: Arc<str> = Arc::from(value);
        self.strings.push(Arc::clone(&shared));
        self.ids.insert(shared, id);
        Some(id)
    }

    fn get(&self, value: &str) -> Option<Id> {
        self.ids.get(value).copied()
    }

    fn resolve(&self, id: Id) -> &str {
        &self.strings[id as usize]
    }
}

/// One level of a conditional probability table.
#[derive(Debug, Default)]
struct Cpt {
    /// The distribution, when this level is a leaf.
    leaf_values: Vec<Id>,
    leaf_probabilities: Vec<f64>,
    /// `deeper`: the parent values and the subtree each selects.
    deeper_values: Vec<Id>,
    deeper: Vec<Cpt>,
    /// `skip`: the subtree for a parent value absent from `deeper`.
    skip: Option<Box<Cpt>>,
}

impl Cpt {
    /// Descends one parent level; `None` is the empty distribution.
    fn child(&self, parent_value: Option<Id>) -> Option<&Cpt> {
        parent_value
            .and_then(|value| self.deeper_values.iter().position(|&k| k == value))
            .map(|i| &self.deeper[i])
            .or(self.skip.as_deref())
    }

    fn leaf(&self) -> impl ExactSizeIterator<Item = (Id, f64)> + '_ {
        self.leaf_values
            .iter()
            .copied()
            .zip(self.leaf_probabilities.iter().copied())
    }

    fn probability(&self, value: Id) -> Option<f64> {
        self.leaf_values
            .iter()
            .position(|&k| k == value)
            .map(|i| self.leaf_probabilities[i])
    }
}

#[derive(Debug)]
struct NodeDef {
    name: Box<str>,
    parent_names: Vec<Box<str>>,
    /// The sampling-order index of each parent, `None` for a parent that is
    /// not a node of the network.
    parents: Vec<Option<usize>>,
    possible_values: Vec<Id>,
    cpt: Cpt,
}

impl NodeDef {
    /// browserforge's `get_probabilities_given_known_values`: the CPT level
    /// selected by the parent values, `None` for the empty distribution.
    fn level(&self, mut parent_value: impl FnMut(usize) -> Option<Id>) -> Option<&Cpt> {
        let mut level = &self.cpt;
        for position in 0..self.parent_names.len() {
            level = level.child(parent_value(position))?;
        }
        Some(level)
    }
}

/// browserforge's draw: one anchor in `[0, 1)`, then the first candidate whose
/// running probability total exceeds it, else the first candidate. The total
/// is not renormalised. No candidate draws nothing and yields `None`.
fn draw(rng: &mut Rng, candidates: impl IntoIterator<Item = (Id, f64)>) -> Option<Id> {
    let mut candidates = candidates.into_iter();
    let (first, first_probability) = candidates.next()?;
    let anchor = rng.next_f64();
    let mut cumulative = first_probability;
    if cumulative > anchor {
        return Some(first);
    }
    for (value, probability) in candidates {
        cumulative += probability;
        if cumulative > anchor {
            return Some(value);
        }
    }
    Some(first)
}

/// browserforge's `sample_according_to_restrictions`: the candidates are the
/// `allowed` values, in their order, that are not banned and have a
/// probability at this level.
fn draw_restricted(rng: &mut Rng, level: &Cpt, allowed: &[Id], banned: &[Id]) -> Option<Id> {
    let usable = |value: &Id| !banned.contains(value);
    let candidates: Vec<(Id, f64)> =
        if allowed.len().saturating_mul(level.leaf_values.len()) > LINEAR_LOOKUP_LIMIT {
            let mut index = HashMap::with_capacity(level.leaf_values.len());
            for (value, probability) in level.leaf() {
                index.entry(value).or_insert(probability);
            }
            allowed
                .iter()
                .filter(|v| usable(v))
                .filter_map(|&v| index.get(&v).map(|&p| (v, p)))
                .collect()
        } else {
            allowed
                .iter()
                .filter(|v| usable(v))
                .filter_map(|&v| level.probability(v).map(|p| (v, p)))
                .collect()
        };
    draw(rng, candidates)
}

/// A Bayesian network that samples browser attributes.
pub struct BayesianNetwork {
    nodes: Vec<NodeDef>,
    by_name: HashMap<Box<str>, usize>,
    interner: Interner,
}

impl fmt::Debug for BayesianNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BayesianNetwork")
            .field(
                "nodes",
                &self.nodes.iter().map(|n| &*n.name).collect::<Vec<_>>(),
            )
            .field("interned_values", &self.interner.strings.len())
            .finish_non_exhaustive()
    }
}

/// A node of a [`BayesianNetwork`].
#[derive(Clone, Copy)]
pub struct Node<'a> {
    network: &'a BayesianNetwork,
    def: &'a NodeDef,
}

impl fmt::Debug for Node<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("name", &self.def.name)
            .field("parent_names", &self.def.parent_names)
            .finish_non_exhaustive()
    }
}

impl<'a> Node<'a> {
    /// The node name.
    #[must_use]
    pub fn name(&self) -> &'a str {
        &self.def.name
    }

    /// The names of the parents, in CPT level order.
    pub fn parent_names(&self) -> impl ExactSizeIterator<Item = &'a str> + use<'a> {
        self.def.parent_names.iter().map(|name| &**name)
    }

    /// The values the node can take, in definition order.
    pub fn possible_values(&self) -> impl ExactSizeIterator<Item = &'a str> + use<'a> {
        let interner = &self.network.interner;
        self.def
            .possible_values
            .iter()
            .map(|&id| interner.resolve(id))
    }

    fn level(&self, parent_values: &Values) -> Option<&'a Cpt> {
        let def: &'a NodeDef = self.def;
        let interner = &self.network.interner;
        def.level(|position| {
            parent_values
                .get(&def.parent_names[position])
                .and_then(|value| interner.get(value))
        })
    }

    /// The distribution of the node given the values of its parents, looked up
    /// by name in `parent_values` (browserforge's
    /// `get_probabilities_given_known_values`). Empty when the CPT has no
    /// entry for those parent values.
    #[must_use]
    pub fn probabilities(&self, parent_values: &Values) -> Vec<(&'a str, f64)> {
        let interner = &self.network.interner;
        self.level(parent_values)
            .map(|level| {
                level
                    .leaf()
                    .map(|(id, p)| (interner.resolve(id), p))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Draws a value given the values of the parents; `None` when the
    /// distribution is empty.
    pub fn sample(&self, rng: &mut Rng, parent_values: &Values) -> Option<&'a str> {
        let level = self.level(parent_values)?;
        draw(rng, level.leaf()).map(|id| self.network.interner.resolve(id))
    }
}

impl BayesianNetwork {
    /// Parses a network from a zip archive holding its `network.json`.
    ///
    /// # Errors
    ///
    /// [`Error::Zip`] when the archive is unreadable, [`Error::Network`] when
    /// the JSON is not a network definition.
    pub fn from_zip(archive: &[u8]) -> crate::Result<Self> {
        Self::from_json(&crate::zip::first_json_entry(archive)?)
    }

    /// Parses a network from its `network.json` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Network`] when the JSON is not a network definition.
    pub fn from_json(json: &[u8]) -> crate::Result<Self> {
        let network_error = |e: serde_json::Error| Error::Network(e.to_string());
        let mut interner = Interner::default();
        let mut deserializer = serde_json::Deserializer::from_slice(json);
        let mut nodes = NetworkSeed(&mut interner)
            .deserialize(&mut deserializer)
            .map_err(network_error)?;
        deserializer.end().map_err(network_error)?;
        let by_name: HashMap<Box<str>, usize> = nodes
            .iter()
            .enumerate()
            .map(|(i, node)| (node.name.clone(), i))
            .collect();
        for node in &mut nodes {
            node.parents = node
                .parent_names
                .iter()
                .map(|parent| by_name.get(parent).copied())
                .collect();
        }
        Ok(Self {
            nodes,
            by_name,
            interner,
        })
    }

    /// The number of nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` for a network without nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The node called `name`.
    #[must_use]
    pub fn node(&self, name: &str) -> Option<Node<'_>> {
        self.by_name.get(name).map(|&i| Node {
            network: self,
            def: &self.nodes[i],
        })
    }

    /// The nodes in sampling order.
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = Node<'_>> {
        self.nodes.iter().map(|def| Node { network: self, def })
    }

    /// browserforge's `generate_sample`: starts from a copy of `fixed`, then
    /// samples every node it does not name, in sampling order, each given the
    /// values chosen so far. A node whose distribution is empty for its
    /// parent values stays out of the sample.
    #[must_use]
    pub fn sample(&self, rng: &mut Rng, fixed: &Values) -> Values {
        let mut sample = fixed.clone();
        for node in self.nodes() {
            if sample.contains_key(node.name()) {
                continue;
            }
            if let Some(value) = node.sample(rng, &sample) {
                sample.insert(node.name(), value.to_owned());
            }
        }
        sample
    }

    /// browserforge's `generate_consistent_sample_when_possible`: a sample in
    /// which every node named in `possibilities` takes one of its listed
    /// values (other nodes range over their possible values). Searches depth
    /// first in sampling order, banning a value whose subtree has no
    /// consistent completion and backtracking when a node runs out of values.
    /// `None` when no consistent sample exists.
    #[must_use]
    pub fn consistent_sample(&self, rng: &mut Rng, possibilities: &Restrictions) -> Option<Values> {
        let allowed: Vec<Cow<'_, [Id]>> = self
            .nodes
            .iter()
            .map(|node| match possibilities.get(&node.name) {
                // A value the network never mentions has no probability
                // anywhere, so dropping it changes no draw.
                Some(values) => {
                    Cow::Owned(values.iter().filter_map(|v| self.interner.get(v)).collect())
                }
                None => Cow::Borrowed(node.possible_values.as_slice()),
            })
            .collect();
        let mut chosen = vec![None; self.nodes.len()];
        if !self.consistent_from(rng, &allowed, &mut chosen, 0) {
            return None;
        }
        Some(
            self.nodes
                .iter()
                .zip(chosen)
                .filter_map(|(node, id)| {
                    id.map(|id| (&*node.name, self.interner.resolve(id).to_owned()))
                })
                .collect(),
        )
    }

    fn consistent_from(
        &self,
        rng: &mut Rng,
        allowed: &[Cow<'_, [Id]>],
        chosen: &mut [Option<Id>],
        depth: usize,
    ) -> bool {
        let Some(node) = self.nodes.get(depth) else {
            return true;
        };
        // The parents precede the node, so their values (and the level they
        // select) stay fixed while this node tries its candidates.
        let Some(level) = node.level(|position| node.parents[position].and_then(|i| chosen[i]))
        else {
            return false;
        };
        let mut banned = Vec::new();
        while let Some(value) = draw_restricted(rng, level, &allowed[depth], &banned) {
            chosen[depth] = Some(value);
            if self.consistent_from(rng, allowed, chosen, depth + 1) {
                return true;
            }
            banned.push(value);
            chosen[depth] = None;
        }
        false
    }

    /// [`BayesianNetwork::sample`] in which every node named in `restrictions`
    /// (and not in `fixed`) takes one of its listed values.
    ///
    /// Without restrictions the draws, and so the result, are exactly those
    /// of [`BayesianNetwork::sample`]. With restrictions the search is depth
    /// first in sampling order, banning a value whose subtree has no
    /// completion and backtracking, as [`BayesianNetwork::consistent_sample`]
    /// does; unrestricted nodes draw from their full distribution and, as in
    /// `sample`, stay out of the result when it is empty. `None` when no
    /// sample satisfies the restrictions.
    #[must_use]
    pub fn restricted_sample(
        &self,
        rng: &mut Rng,
        fixed: &Values,
        restrictions: &Restrictions,
    ) -> Option<Values> {
        let allowed: Vec<Option<Vec<Id>>> = self
            .nodes
            .iter()
            .map(|node| {
                if fixed.contains_key(&node.name) {
                    return None;
                }
                restrictions
                    .get(&node.name)
                    .map(|values| values.iter().filter_map(|v| self.interner.get(v)).collect())
            })
            .collect();
        let mut chosen: Vec<Option<Id>> = self
            .nodes
            .iter()
            .map(|node| fixed.get(&node.name).and_then(|v| self.interner.get(v)))
            .collect();
        if !self.restricted_from(rng, fixed, &allowed, &mut chosen, 0) {
            return None;
        }
        let mut sample = fixed.clone();
        for (node, id) in self.nodes.iter().zip(chosen) {
            if fixed.contains_key(&node.name) {
                continue;
            }
            if let Some(id) = id {
                sample.insert(&*node.name, self.interner.resolve(id).to_owned());
            }
        }
        Some(sample)
    }

    fn restricted_from(
        &self,
        rng: &mut Rng,
        fixed: &Values,
        allowed: &[Option<Vec<Id>>],
        chosen: &mut [Option<Id>],
        depth: usize,
    ) -> bool {
        let Some(node) = self.nodes.get(depth) else {
            return true;
        };
        if fixed.contains_key(&node.name) {
            return self.restricted_from(rng, fixed, allowed, chosen, depth + 1);
        }
        // A parent outside the network is looked up by name among the fixed
        // values, as `sample` does.
        let level = node.level(|position| match node.parents[position] {
            Some(i) => chosen[i],
            None => fixed
                .get(&node.parent_names[position])
                .and_then(|v| self.interner.get(v)),
        });
        let mut banned = Vec::new();
        loop {
            let drawn = match (&allowed[depth], level) {
                (_, None) => None,
                (Some(list), Some(level)) => draw_restricted(rng, level, list, &banned),
                (None, Some(level)) => draw(rng, level.leaf().filter(|(v, _)| !banned.contains(v))),
            };
            let Some(value) = drawn else {
                // An unrestricted node with an empty distribution stays out
                // of the sample; anything else has run out of values.
                if allowed[depth].is_none() && banned.is_empty() {
                    chosen[depth] = None;
                    return self.restricted_from(rng, fixed, allowed, chosen, depth + 1);
                }
                return false;
            };
            chosen[depth] = Some(value);
            if self.restricted_from(rng, fixed, allowed, chosen, depth + 1) {
                return true;
            }
            banned.push(value);
            chosen[depth] = None;
        }
    }

    /// browserforge's `get_possible_values`: extends the constraints with the
    /// values they induce on the parents of each constrained node, then
    /// intersects the constraints that meet on a node.
    ///
    /// For each constrained node the parents may take the values on any CPT
    /// path (ignoring `skip`) that ends in one of the node's allowed values.
    /// Every list keeps first-seen order.
    ///
    /// # Errors
    ///
    /// [`Error::TooRestrictive`] when a constraint is empty or an intersection
    /// is; [`Error::UnknownNode`] when a constraint names no node.
    pub fn possible_values(&self, restrictions: &Restrictions) -> crate::Result<Restrictions> {
        let mut sets = Vec::with_capacity(restrictions.len());
        for (name, values) in restrictions {
            if values.is_empty() {
                return Err(Error::TooRestrictive);
            }
            let &index = self
                .by_name
                .get(name)
                .ok_or_else(|| Error::UnknownNode(name.to_owned()))?;
            let node = &self.nodes[index];
            let valid: HashSet<Id> = values.iter().filter_map(|v| self.interner.get(v)).collect();
            let mut paths = PathLevels::default();
            paths.collect(&node.cpt, &valid, &mut Vec::new());
            let mut set: Restrictions = node
                .parent_names
                .iter()
                .zip(paths.levels)
                .map(|(parent, (ids, _))| {
                    let parent_values = ids
                        .iter()
                        .map(|&id| self.interner.resolve(id).to_owned())
                        .collect();
                    (&**parent, parent_values)
                })
                .collect();
            set.insert(name, values.clone());
            sets.push(set);
        }

        let mut result = Restrictions::new();
        for set in sets {
            for (name, values) in set {
                match result.get_mut(&name) {
                    Some(existing) => {
                        let known: HashSet<&str> = existing.iter().map(String::as_str).collect();
                        let intersection: Vec<String> = values
                            .into_iter()
                            .filter(|v| known.contains(v.as_str()))
                            .collect();
                        if intersection.is_empty() {
                            return Err(Error::TooRestrictive);
                        }
                        *existing = intersection;
                    }
                    None => {
                        result.insert(name, values);
                    }
                }
            }
        }
        Ok(result)
    }
}

/// browserforge's `filter_by_last_level_keys` over the `undeeper`ed tree
/// (`skip` removed): per level, the union of the keys on every path that ends
/// in a valid leaf value, in first-seen order.
#[derive(Default)]
struct PathLevels {
    levels: Vec<(Vec<Id>, HashSet<Id>)>,
}

impl PathLevels {
    fn collect(&mut self, level: &Cpt, valid: &HashSet<Id>, path: &mut Vec<Id>) {
        for value in &level.leaf_values {
            if valid.contains(value) {
                self.merge(path);
            }
        }
        for (&key, child) in level.deeper_values.iter().zip(&level.deeper) {
            path.push(key);
            self.collect(child, valid, path);
            path.pop();
        }
    }

    /// `array_zip`: the first path initialises the levels, later ones union
    /// into them; like Python's `zip`, the shorter side bounds the result.
    fn merge(&mut self, path: &[Id]) {
        if self.levels.is_empty() {
            self.levels = path
                .iter()
                .map(|&k| (vec![k], HashSet::from([k])))
                .collect();
            return;
        }
        self.levels.truncate(path.len());
        for ((ordered, seen), &key) in self.levels.iter_mut().zip(path) {
            if seen.insert(key) {
                ordered.push(key);
            }
        }
    }
}

fn cached(
    cell: &'static OnceLock<crate::Result<BayesianNetwork>>,
    archive: &[u8],
) -> crate::Result<&'static BayesianNetwork> {
    cell.get_or_init(|| BayesianNetwork::from_zip(archive))
        .as_ref()
        .map_err(Clone::clone)
}

/// The input network, parsed once per process.
///
/// # Errors
///
/// The parse error of the embedded archive (none for the shipped data).
pub fn input_network() -> crate::Result<&'static BayesianNetwork> {
    static NETWORK: OnceLock<crate::Result<BayesianNetwork>> = OnceLock::new();
    cached(&NETWORK, INPUT_NETWORK_ZIP)
}

/// The HTTP header network, parsed once per process.
///
/// # Errors
///
/// The parse error of the embedded archive (none for the shipped data).
pub fn header_network() -> crate::Result<&'static BayesianNetwork> {
    static NETWORK: OnceLock<crate::Result<BayesianNetwork>> = OnceLock::new();
    cached(&NETWORK, HEADER_NETWORK_ZIP)
}

/// The browser fingerprint network, parsed once per process.
///
/// # Errors
///
/// The parse error of the embedded archive (none for the shipped data).
pub fn fingerprint_network() -> crate::Result<&'static BayesianNetwork> {
    static NETWORK: OnceLock<crate::Result<BayesianNetwork>> = OnceLock::new();
    cached(&NETWORK, FINGERPRINT_NETWORK_ZIP)
}

// ---------------------------------------------------------------------------
// Streaming JSON parse: the CPT tree is built straight from the token stream,
// interning every string as it is read.

/// A map key matched against a fixed field list.
#[derive(Clone, Copy)]
struct Field(&'static [&'static str]);

impl<'de> DeserializeSeed<'de> for Field {
    type Value = Option<usize>;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for Field {
    type Value = Option<usize>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a field name")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(self.0.iter().position(|field| *field == value))
    }
}

/// An interned string.
struct IdSeed<'i>(&'i mut Interner);

impl<'de> DeserializeSeed<'de> for IdSeed<'_> {
    type Value = Id;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for IdSeed<'_> {
    type Value = Id;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.0
            .intern(value)
            .ok_or_else(|| E::custom("more than 2^32 distinct strings"))
    }
}

/// A list of interned strings.
struct IdListSeed<'i>(&'i mut Interner);

impl<'de> DeserializeSeed<'de> for IdListSeed<'_> {
    type Value = Vec<Id>;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for IdListSeed<'_> {
    type Value = Vec<Id>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of strings")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut ids = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(id) = seq.next_element_seed(IdSeed(&mut *self.0))? {
            ids.push(id);
        }
        Ok(ids)
    }
}

/// `{"nodes": [...]}`.
struct NetworkSeed<'i>(&'i mut Interner);

impl<'de> DeserializeSeed<'de> for NetworkSeed<'_> {
    type Value = Vec<NodeDef>;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for NetworkSeed<'_> {
    type Value = Vec<NodeDef>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a network definition object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut nodes = None;
        while let Some(field) = map.next_key_seed(Field(&["nodes"]))? {
            if field.is_some() {
                nodes = Some(map.next_value_seed(NodeListSeed(&mut *self.0))?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        nodes.ok_or_else(|| de::Error::missing_field("nodes"))
    }
}

struct NodeListSeed<'i>(&'i mut Interner);

impl<'de> DeserializeSeed<'de> for NodeListSeed<'_> {
    type Value = Vec<NodeDef>;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for NodeListSeed<'_> {
    type Value = Vec<NodeDef>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of nodes")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut nodes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(node) = seq.next_element_seed(NodeSeed(&mut *self.0))? {
            nodes.push(node);
        }
        Ok(nodes)
    }
}

const NODE_FIELDS: &[&str] = &[
    "name",
    "parentNames",
    "possibleValues",
    "conditionalProbabilities",
];

struct NodeSeed<'i>(&'i mut Interner);

impl<'de> DeserializeSeed<'de> for NodeSeed<'_> {
    type Value = NodeDef;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for NodeSeed<'_> {
    type Value = NodeDef;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a network node object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut name: Option<String> = None;
        let mut parent_names: Vec<String> = Vec::new();
        let mut possible_values = Vec::new();
        let mut cpt = None;
        while let Some(field) = map.next_key_seed(Field(NODE_FIELDS))? {
            match field {
                Some(0) => name = Some(map.next_value()?),
                Some(1) => parent_names = map.next_value()?,
                Some(2) => possible_values = map.next_value_seed(IdListSeed(&mut *self.0))?,
                Some(3) => cpt = Some(map.next_value_seed(CptSeed(&mut *self.0))?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(NodeDef {
            name: name.ok_or_else(|| de::Error::missing_field("name"))?.into(),
            parent_names: parent_names
                .into_iter()
                .map(String::into_boxed_str)
                .collect(),
            parents: Vec::new(),
            possible_values,
            cpt: cpt.ok_or_else(|| de::Error::missing_field("conditionalProbabilities"))?,
        })
    }
}

/// A key of a CPT level: one of the two structural keys, or a node value.
enum CptKey {
    Deeper,
    Skip,
    Value(Id),
}

struct CptKeySeed<'i>(&'i mut Interner);

impl<'de> DeserializeSeed<'de> for CptKeySeed<'_> {
    type Value = CptKey;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for CptKeySeed<'_> {
    type Value = CptKey;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a CPT key")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        match value {
            "deeper" => Ok(CptKey::Deeper),
            "skip" => Ok(CptKey::Skip),
            _ => IdSeed(self.0).visit_str(value).map(CptKey::Value),
        }
    }
}

/// One CPT level.
struct CptSeed<'i>(&'i mut Interner);

impl<'de> DeserializeSeed<'de> for CptSeed<'_> {
    type Value = Cpt;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for CptSeed<'_> {
    type Value = Cpt;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a conditional probability table")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut cpt = Cpt::default();
        while let Some(key) = map.next_key_seed(CptKeySeed(&mut *self.0))? {
            let structural = match key {
                CptKey::Value(id) => {
                    cpt.leaf_values.push(id);
                    cpt.leaf_probabilities.push(map.next_value()?);
                    continue;
                }
                CptKey::Deeper => (true, "deeper"),
                CptKey::Skip => (false, "skip"),
            };
            match map.next_value_seed(EntrySeed {
                interner: &mut *self.0,
                deeper: structural.0,
            })? {
                Entry::Deeper(values, children) => {
                    cpt.deeper_values = values;
                    cpt.deeper = children;
                }
                Entry::Skip(child) => cpt.skip = Some(Box::new(child)),
                // A node value literally called "deeper" or "skip".
                Entry::Probability(probability) => {
                    let id = IdSeed(&mut *self.0).visit_str::<A::Error>(structural.1)?;
                    cpt.leaf_values.push(id);
                    cpt.leaf_probabilities.push(probability);
                }
            }
        }
        Ok(cpt)
    }
}

/// The value under a `deeper` or `skip` key: a subtree, or a probability
/// when the key is in fact a node value.
enum Entry {
    Deeper(Vec<Id>, Vec<Cpt>),
    Skip(Cpt),
    Probability(f64),
}

struct EntrySeed<'i> {
    interner: &'i mut Interner,
    deeper: bool,
}

impl<'de> DeserializeSeed<'de> for EntrySeed<'_> {
    type Value = Entry;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for EntrySeed<'_> {
    type Value = Entry;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a CPT subtree or a probability")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        if !self.deeper {
            return CptSeed(self.interner).visit_map(map).map(Entry::Skip);
        }
        let mut values = Vec::with_capacity(map.size_hint().unwrap_or(0));
        let mut children = Vec::with_capacity(values.capacity());
        while let Some(value) = map.next_key_seed(IdSeed(&mut *self.interner))? {
            values.push(value);
            children.push(map.next_value_seed(CptSeed(&mut *self.interner))?);
        }
        Ok(Entry::Deeper(values, children))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(Entry::Probability(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        let integer: de::value::U64Deserializer<E> = value.into_deserializer();
        f64::deserialize(integer).map(Entry::Probability)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        let integer: de::value::I64Deserializer<E> = value.into_deserializer();
        f64::deserialize(integer).map(Entry::Probability)
    }
}
