//! Keeps lint suppressions out of the workspace's Rust sources, as
//! `bindings/python/tests/test_no_suppressions.py` does for the Python ones:
//! no `.rs` file under `crates/*/src`, `crates/*/tests` or `bindings/*/src`
//! may hold an `allow` or `expect` attribute, inner or outer, outside
//! comments and literals. A lint that fires is fixed, not silenced.

use std::fs;
use std::path::{Path, PathBuf};

/// The workspace root, when this crate sits in it as
/// `crates/opentele2-core`; `None` otherwise, as in a packaged crate.
fn workspace_root() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("..").join("..");
    let this_crate = fs::canonicalize(root.join("crates").join("opentele2-core")).ok()?;
    (this_crate == fs::canonicalize(manifest).ok()?).then_some(root)
}

/// Every `.rs` file under `dir`, recursively; none when `dir` is absent.
fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry
            .unwrap_or_else(|error| panic!("cannot list {}: {error}", dir.display()))
            .path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// The subdirectories of `dir`, sorted; none when `dir` is absent.
fn subdirectories(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// The `.rs` files the rule covers, sorted.
fn covered_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for krate in subdirectories(&root.join("crates")) {
        rust_files(&krate.join("src"), &mut files);
        rust_files(&krate.join("tests"), &mut files);
    }
    for binding in subdirectories(&root.join("bindings")) {
        rust_files(&binding.join("src"), &mut files);
    }
    files.sort();
    files
}

/// The length of the nested block comment `rest` starts with.
fn block_comment_len(rest: &[char]) -> usize {
    let mut depth = 0_usize;
    let mut at = 0;
    while at < rest.len() {
        if rest[at..].starts_with(&['/', '*']) {
            depth += 1;
            at += 2;
        } else if rest[at..].starts_with(&['*', '/']) {
            depth -= 1;
            at += 2;
            if depth == 0 {
                return at;
            }
        } else {
            at += 1;
        }
    }
    rest.len()
}

/// The length of the string literal (plain, byte, C or raw) `rest` starts
/// with, if it starts with one. A prefix letter right after an identifier
/// character is part of that identifier, not a prefix.
fn string_literal_len(rest: &[char], after_identifier: bool) -> Option<usize> {
    let mut at = 0;
    if !after_identifier {
        if matches!(rest.first(), Some('b' | 'c')) {
            at += 1;
        }
        if rest.get(at) == Some(&'r') {
            let hashes = rest[at + 1..].iter().take_while(|&&ch| ch == '#').count();
            if rest.get(at + 1 + hashes) != Some(&'"') {
                return None;
            }
            let closing = |end: usize| {
                rest[end] == '"'
                    && rest
                        .get(end + 1..end + 1 + hashes)
                        .is_some_and(|tail| tail.iter().all(|&ch| ch == '#'))
            };
            let body = at + 2 + hashes;
            return Some(
                (body..rest.len())
                    .find(|&end| closing(end))
                    .map_or(rest.len(), |end| end + 1 + hashes),
            );
        }
    }
    if rest.get(at) != Some(&'"') {
        return None;
    }
    let mut end = at + 1;
    while end < rest.len() {
        match rest[end] {
            '\\' => end += 2,
            '"' => return Some(end + 1),
            _ => end += 1,
        }
    }
    Some(rest.len())
}

/// The length of the character literal `rest` starts with, if its `'`
/// opens one rather than a lifetime or label.
fn char_literal_len(rest: &[char]) -> Option<usize> {
    if rest.get(1) == Some(&'\\') {
        // The escaped character itself may be a `'`.
        let close = rest.get(3..)?.iter().position(|&ch| ch == '\'')?;
        return Some(close + 4);
    }
    (rest.get(2) == Some(&'\'')).then_some(3)
}

/// `source` with every comment and literal blanked to spaces, newlines
/// kept, so line numbers still hold.
fn code_only(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut code = String::with_capacity(source.len());
    let mut at = 0;
    while at < chars.len() {
        let rest = &chars[at..];
        let after_identifier = at > 0 && (chars[at - 1].is_alphanumeric() || chars[at - 1] == '_');
        let skipped = if rest.starts_with(&['/', '/']) {
            rest.iter().position(|&ch| ch == '\n').unwrap_or(rest.len())
        } else if rest.starts_with(&['/', '*']) {
            block_comment_len(rest)
        } else if let Some(len) = string_literal_len(rest, after_identifier) {
            len
        } else if rest[0] == '\'' {
            char_literal_len(rest).unwrap_or(0)
        } else {
            0
        };
        if skipped == 0 {
            code.push(rest[0]);
            at += 1;
        } else {
            let end = (at + skipped).min(chars.len());
            code.extend(
                chars[at..end]
                    .iter()
                    .map(|&ch| if ch == '\n' { '\n' } else { ' ' }),
            );
            at = end;
        }
    }
    code
}

/// `rest` without its leading whitespace.
fn skip_whitespace(rest: &[char]) -> &[char] {
    let blank = rest.iter().take_while(|ch| ch.is_whitespace()).count();
    &rest[blank..]
}

/// Whether the code after a `#` continues as an `allow` or `expect`
/// attribute, outer or inner, with any whitespace between its tokens.
fn opens_suppression(after_hash: &[char]) -> bool {
    let mut rest = skip_whitespace(after_hash);
    if let Some(inner) = rest.strip_prefix(&['!']) {
        rest = skip_whitespace(inner);
    }
    let Some(rest) = rest.strip_prefix(&['[']) else {
        return false;
    };
    let rest = skip_whitespace(rest);
    ["allow", "expect"].iter().any(|name| {
        let name: Vec<char> = name.chars().collect();
        rest.strip_prefix(name.as_slice())
            .is_some_and(|args| skip_whitespace(args).first() == Some(&'('))
    })
}

/// The 1-based lines of `source` on which a suppression attribute starts.
fn suppression_lines(source: &str) -> Vec<usize> {
    let chars: Vec<char> = code_only(source).chars().collect();
    let mut lines = Vec::new();
    let mut line = 1;
    for (at, &ch) in chars.iter().enumerate() {
        if ch == '\n' {
            line += 1;
        } else if ch == '#' && opens_suppression(&chars[at + 1..]) {
            lines.push(line);
        }
    }
    lines
}

#[test]
fn no_rust_source_suppresses_a_lint() {
    let Some(root) = workspace_root() else {
        println!(
            "note: no workspace around {}; the suppression scan is skipped",
            env!("CARGO_MANIFEST_DIR")
        );
        return;
    };
    let files = covered_files(&root);
    assert!(
        files
            .iter()
            .any(|file| file.ends_with("no_suppressions.rs")),
        "the scan must cover this file; found {} files",
        files.len()
    );
    let mut found = Vec::new();
    for file in &files {
        let source = fs::read_to_string(file)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", file.display()));
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        let source_lines: Vec<&str> = source.lines().collect();
        for line in suppression_lines(&source) {
            let text = source_lines.get(line - 1).map_or("", |text| text.trim());
            found.push(format!("{shown}:{line}: {text}"));
        }
    }
    assert!(
        found.is_empty(),
        "lint suppressions; fix the lint instead:\n{}",
        found.join("\n")
    );
}

#[test]
fn every_suppression_form_is_found() {
    let source = "#![allow(missing_docs)]\n\
                  #![expect(missing_docs)]\n\
                  #[allow(dead_code)]\n\
                  #[expect(dead_code, reason = \"x\")]\n\
                  # ! [ allow ( unused ) ]\n\
                  fn f() {\n    #[allow(clippy::float_cmp)] let _ = 1;\n}\n\
                  #[expect(\n    dead_code\n)]\n";
    assert_eq!(suppression_lines(source), [1, 2, 3, 4, 5, 7, 9]);
}

#[test]
fn comments_literals_and_other_attributes_are_not_suppressions() {
    let source = r##"// #[allow(dead_code)]
/// #[expect(dead_code)]
/* #[allow(x)] /* nested #[allow(y)] */ #[expect(z)] */
const A: &str = "#[allow(dead_code)] \" #[expect(x)]";
const B: &str = r#"#[allow(dead_code)] " #[expect(x)]"#;
const C: &[u8] = b"#[allow(x)]";
const D: char = '"';
const E: char = '\'';
fn f<'a>(x: &'a str) -> &'a str { x }
#[derive(Debug)]
#[allow_internal_unstable(x)]
#[cfg_attr(test, derive(Clone))]
#[allow(dead_code)]
"##;
    assert_eq!(suppression_lines(source), [13]);
}
