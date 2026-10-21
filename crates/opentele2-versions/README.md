# opentele2-versions

The current official Telegram client versions, fetched from their public release feeds, plus
the stable Chrome and Firefox versions, as a patch onto `opentele2_core::api::Versions`. Part of
[opentele2](https://github.com/DedInc/opentele2).

Sources: Telegram Desktop, Android, Telegram X, iOS, macOS, Web K, Web A, Chrome and Firefox,
queried in parallel. A source that fails or times out leaves its fields unset.

```rust
use std::time::Duration;

use opentele2_core::api::Versions;

fn main() {
    let mut versions = Versions::offline();
    opentele2_versions::fetch_all(Duration::from_secs(10)).apply(&mut versions);
    println!("{versions:?}");
}
```

License: MIT.
