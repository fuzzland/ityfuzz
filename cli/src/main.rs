mod evm;
mod r#move;

use crate::evm::{evm_main, EvmArgs};
use crate::r#move::{move_main, MoveArgs};
use clap::Parser;
use clap::Subcommand;
use std::env;

pub fn init_sentry() {
    let _guard = sentry::init(("https://96f3517bd77346ea835d28f956a84b9d@o4504503751344128.ingest.sentry.io/4504503752523776", sentry::ClientOptions {
        release: sentry::release_name!(),
        ..Default::default()
    }));
    if let Ok(value) = env::var("NO_TELEMETRY") {
        if value == "1" {
            println!("Telemetry is disabled.");
            unsafe {
                ityfuzz::telemetry::TELEMETRY_ENABLED = false;
            }
        }
    }
}

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    EVM(EvmArgs),
    MOVE(MoveArgs),
}

fn main() {
    init_sentry();
    let args = Cli::parse();
    match args.command {
        Commands::EVM(args) => {
            evm_main(args);
        }
        Commands::MOVE(args) => {
            move_main(args);
        }
    }
}
