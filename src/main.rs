// SPDX-License-Identifier: BSD-3-Clause

use std::{path::PathBuf, sync::Arc, time::Duration};

use eyre::{Ok, OptionExt, Result};
use fuser::{MountOption, SessionACL};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use tokio::{
	select, signal,
	sync::{
		Mutex,
		mpsc::{self, UnboundedSender},
	},
	task::{JoinSet, spawn_blocking},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::{
	Layer,
	filter::{EnvFilter, LevelFilter},
	fmt,
	layer::SubscriberExt,
	util::SubscriberInitExt,
};

use crate::{fs::FoxyFs, sys::SYS_INFO};

pub(crate) mod cli;
pub(crate) mod fs;
pub(crate) mod sys;

fn initialize_tracing(log_level: LevelFilter) -> Result<()> {
	Ok(tracing_subscriber::registry()
		.with(cfg!(debug_assertions).then(|| {
			console_subscriber::spawn().with_filter(
				#[allow(
					clippy::unwrap_used,
					reason = "These `Directive` strings are hard-coded and as correct as we can \
					          ensure, and there is no way to construct them in a more-safe manner \
					          other than `.parse()`"
				)]
				EnvFilter::builder()
					.with_default_directive(LevelFilter::ERROR.into())
					.from_env_lossy()
					.add_directive("tokio=trace".parse().unwrap())
					.add_directive("runtime=trace".parse().unwrap()),
			)
		}))
		.with(
			fmt::layer().with_filter(
				EnvFilter::builder()
					.with_default_directive(log_level.into())
					.with_env_var("FOXY_LOG_LEVEL")
					.from_env_lossy()
					.add_directive("tokio=error".parse()?)
					.add_directive("runtime=error".parse()?)
					.add_directive("mio=error".parse()?)
					.add_directive("fuser=warn".parse()?),
			),
		)
		.with(tracing_error::ErrorLayer::default())
		.try_init()?)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
	color_eyre::install()?;

	let cmd = cli::init_cli()?;
	let args = cmd.clone().get_matches();

	initialize_tracing(match args.get_count("verbose") {
		0 => LevelFilter::INFO,
		1 => LevelFilter::DEBUG,
		_ => LevelFilter::TRACE,
	})?;

	let _ = SYS_INFO.get_or_init(|| {
		Arc::new(Mutex::new(System::new_with_specifics(
			RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
		)))
	});

	let mountpoint = args
		.get_one::<String>("FILE_MOUNT")
		.ok_or_eyre("Unable to get FILE_MOUNT")?
		.clone();

	let mut backing = PathBuf::new();
	backing.push(
		args.get_one::<String>("TARGET_FILE")
			.ok_or_eyre("Unable to get TARGET_FILE")?
			.clone(),
	);

	// XXX(aki): This is hacky but shut up
	let _ = (!backing.exists())
		.then_some(0)
		.ok_or_eyre("Backing file does not exist");

	info!("Proxy target: {}", mountpoint);
	info!("Backing file: {:?}", backing);

	let cow = if let Some(cow_file) = args.get_one::<String>("cow") {
		let mut cow = PathBuf::new();
		cow.push(cow_file);

		info!("CoW file: {:?}", cow);

		Some(cow)
	} else {
		warn!("No CoW file specified, write-through enabled");

		None
	};

	let mut fs = FoxyFs::new()?;

	fs.add_proxy(backing, cow, None)?;

	let mut options = fuser::Config::default();
	options.mount_options.append(&mut vec![
		MountOption::AutoUnmount,
		MountOption::FSName("FOXY".to_string()),
	]);
	options.acl = SessionACL::RootAndOwner;

	let cancel_token = CancellationToken::new();

	let session = fuser::Session::new(fs, mountpoint, &options)?.spawn()?;

	select! {
		_ = signal::ctrl_c() => {},
		// _ = shutdown_recv.recv() => {},
	}

	info!("Caught shutdown signal, stopping");
	cancel_token.cancel();

	// select! {
	// 	// _ = tasks.join_all() => {},
	// 	_ = tokio::time::sleep(Duration::from_secs(15)) => {
	// 		warn!("Tasks did not all join! Forcing shutdown");
	// 	}
	// }

	info!("Unmounting filesystem");
	session.umount_and_join()?;
	Ok(())
}
