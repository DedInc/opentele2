# opentele2-grammers

The [grammers](https://github.com/Lonami/grammers) 0.11 bridge of
[opentele2](https://github.com/DedInc/opentele2): grammers `SessionData` from a Telegram Desktop
tdata account and back, and `initConnection` params from an official API profile.

With the feature `client`: QR login with 2FA, listing and terminating sessions, the sessions
table, the seven consistency checks and tdata from a client session.

```rust
use std::sync::Arc;

use grammers_client::Client;
use grammers_mtsender::SenderPool;
use grammers_session::storages::MemorySession;
use opentele2_core::api::{self, Versions};
use opentele2_core::tdata::TData;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tdata = TData::load("tdata", b"", None)?;
    let account = tdata.main_account().ok_or("no account")?;
    let desktop = api::profile(api::Client::Desktop, &Versions::offline());

    let session = Arc::new(MemorySession::from(opentele2_grammers::session_data(account)));
    let params = opentele2_grammers::connection_params(&desktop);
    let pool = SenderPool::with_configuration(session, desktop.api_id, params);
    let client = Client::new(pool.handle);
    let runner = tokio::spawn(pool.runner.run());
    println!("{:?}", client.get_me().await?.username());
    client.disconnect();
    runner.abort();
    Ok(())
}
```

grammers 0.11 has no `lang_pack` field and sends no `params` in `initConnection`; the
[crate docs](https://docs.rs/opentele2-grammers) describe the gap.

License: MIT.
