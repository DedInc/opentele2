# opentele2-browser

Browser HTTP headers and full browser fingerprints sampled from Bayesian networks: a Rust port
of [browserforge](https://github.com/daijro/browserforge) over the
[Apify fingerprint datapoints](https://github.com/apify/fingerprint-suite). Part of
[opentele2](https://github.com/DedInc/opentele2).

- Deterministic by seed: the same seed and options give byte-identical output here, in Python
  (`opentele2.browser`) and in Node (`generateHeaders`, `generateFingerprint`).
- Fixes seven browserforge defects: Sec-Fetch values, OS relaxation, HTTP/1 fallback, Edge
  detection, the user-agent constraint, the locale cap and request-dependent headers.

```rust
use opentele2_browser::{Browser, FingerprintOptions, HeaderOptions, Screen};

fn main() -> opentele2_browser::Result<()> {
    let options = HeaderOptions { browsers: vec![Browser::new("chrome")], ..HeaderOptions::default() };
    for (name, value) in opentele2_browser::generate_headers(Some("my-id"), &options)?.iter() {
        println!("{name}: {value}");
    }
    let screen = Some(Screen { max_width: Some(1920), ..Screen::default() });
    let options = FingerprintOptions { screen, ..FingerprintOptions::default() };
    let fingerprint = opentele2_browser::generate_fingerprint(Some("42"), &options)?;
    println!("{}", fingerprint.navigator.user_agent);
    Ok(())
}
```

License: Apache-2.0. See [NOTICE](NOTICE) for browserforge and the Apify data.
