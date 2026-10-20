//! A small insertion-ordered string map, the shape of browserforge's dicts.

/// A map from node names to `V` that iterates in insertion order.
///
/// Inserting an existing key replaces its value in place, as a Python dict
/// does. Lookups are linear: the maps hold one entry per network node, a few
/// dozen at most, where a scan beats hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedMap<V> {
    entries: Vec<(String, V)>,
}

/// Node name to value, in insertion order: a (partial) network sample.
pub type Values = OrderedMap<String>;

/// Node name to the list of values it may take, in insertion order.
pub type Restrictions = OrderedMap<Vec<String>>;

impl<V> Default for OrderedMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> OrderedMap<V> {
    /// Creates an empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the map holds no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn position(&self, key: &str) -> Option<usize> {
        self.entries.iter().position(|(k, _)| k == key)
    }

    /// Returns the value stored under `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&V> {
        self.position(key).map(|i| &self.entries[i].1)
    }

    /// Returns a mutable reference to the value stored under `key`.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.position(key).map(|i| &mut self.entries[i].1)
    }

    /// Returns `true` when `key` is present.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.position(key).is_some()
    }

    /// Inserts `value` under `key`, returning the value it replaced. A new key
    /// goes last; an existing key keeps its position.
    pub fn insert(&mut self, key: impl Into<String>, value: V) -> Option<V> {
        let key = key.into();
        if let Some(i) = self.position(&key) {
            return Some(std::mem::replace(&mut self.entries[i].1, value));
        }
        self.entries.push((key, value));
        None
    }

    /// Removes `key`, keeping the order of the remaining entries.
    pub fn remove(&mut self, key: &str) -> Option<V> {
        self.position(key).map(|i| self.entries.remove(i).1)
    }

    /// Iterates over the entries in insertion order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &V)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Iterates over the keys in insertion order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }
}

impl<K: Into<String>, V> FromIterator<(K, V)> for OrderedMap<V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Self::new();
        map.extend(iter);
        map
    }
}

impl<K: Into<String>, V> Extend<(K, V)> for OrderedMap<V> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

impl<V> IntoIterator for OrderedMap<V> {
    type Item = (String, V);
    type IntoIter = std::vec::IntoIter<(String, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a, V> IntoIterator for &'a OrderedMap<V> {
    type Item = (&'a str, &'a V);
    type IntoIter =
        std::iter::Map<std::slice::Iter<'a, (String, V)>, fn(&'a (String, V)) -> (&'a str, &'a V)>;

    fn into_iter(self) -> Self::IntoIter {
        fn split<V>(entry: &(String, V)) -> (&str, &V) {
            (entry.0.as_str(), &entry.1)
        }
        self.entries.iter().map(split)
    }
}
