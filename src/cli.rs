// SPDX-License-Identifier: BSD-3-Clause

use clap::{Arg, ArgAction, Command};
use eyre::Result;

pub(crate) fn init_cli() -> Result<Command> {
	let cmd = Command::new(env!("CARGO_PKG_NAME"))
		.version(env!("CARGO_PKG_VERSION"))
		.about(env!("CARGO_PKG_DESCRIPTION"))
		.arg(
			Arg::new("verbose")
				.short('v')
				.action(ArgAction::Count)
				.help("Enable Verbose Logging"),
		)
		.arg(
			Arg::new("FILE_MOUNT")
				.required(true)
				.index(1)
				.help("The target to mount at"),
		)
		.arg(
			Arg::new("TARGET_FILE")
				.required(true)
				.index(2)
				.help("The target file to proxy"),
		)
		.arg(Arg::new("cow").short('c').help("Set a backing COW file"));

	Ok(cmd)
}
