// SPDX-License-Identifier: BSD-3-Clause

use std::{
	fmt::Display,
	path::PathBuf,
	sync::{Arc, OnceLock},
};

use sysinfo::{Pid, ProcessRefreshKind, System};
use tokio::sync::Mutex;

pub(crate) static SYS_INFO: OnceLock<Arc<Mutex<System>>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct ProcInfo {
	pid:  u32,
	exe:  Option<PathBuf>,
	name: String,
}

pub(crate) fn get_proc_info(pid: u32) -> Option<ProcInfo> {
	if pid == 0 {
		return None;
	}

	let mut info = SYS_INFO.get()?.blocking_lock();
	let sysinfo_pid = Pid::from_u32(pid);

	if let Some(proc) = info.process(sysinfo_pid) {
		Some(proc)
	} else {
		if info.refresh_processes_specifics(
			sysinfo::ProcessesToUpdate::Some(&[sysinfo_pid]),
			true,
			ProcessRefreshKind::everything()
				.without_cpu()
				.without_memory()
				.without_user()
				.without_tasks()
				.without_root()
				.without_cwd()
				.without_environ()
				.without_cmd()
				.without_disk_usage(),
		) == 0
		{
			return None;
		}
		info.process(sysinfo_pid)
	}
	.map(|proc| ProcInfo {
		pid,
		exe: proc.exe().map(|exe| {
			let mut exe_path = PathBuf::new();
			exe_path.push(exe);
			exe_path
		}),
		name: proc.name().to_string_lossy().to_string(),
	})
}

impl Display for ProcInfo {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{} ({})", self.pid, self.name)
	}
}
