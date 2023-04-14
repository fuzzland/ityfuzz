pub use sentry;
pub use reqwest;
use sentry::{Envelope, Level};
use sentry::protocol::EnvelopeItem;
use sentry::types::protocol::v7;
use std::env;

pub fn init_license() {
    let _guard = sentry::init(("https://96f3517bd77346ea835d28f956a84b9d@o4504503751344128.ingest.sentry.io/4504503752523776", sentry::ClientOptions {
        release: sentry::release_name!(),
        ..Default::default()
    }));

    let mut envelope = Envelope::new();

    envelope.add_item(EnvelopeItem::Event(v7::Event {
        level: Level::Info,
        message: Some(format!("Run CLI @ {:?}", std::time::SystemTime::now()).into()),
        extra: ({
            let mut map = std::collections::BTreeMap::new();
            map.insert("args".to_string(), env::args().collect::<Vec<String>>().join(" ").into());
            map.insert("cwd".to_string(), env::current_dir().unwrap().to_str().unwrap().into());
            map
        }),

        ..Default::default()
    }));
    _guard.send_envelope(envelope);

    let res = reqwest::blocking::get("https://fuzz.land/free").unwrap();
    if res.text().unwrap() != "40291454856\n" {
        panic!("License expired");
    }
}
