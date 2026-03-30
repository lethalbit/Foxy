// SPDX-License-Identifier: BSD-3-Clause

use std::{
	collections::BTreeMap,
	fmt::Debug,
	fs,
	io::Write,
	os::unix::fs::{MetadataExt, PermissionsExt},
	path::{Path, PathBuf},
	sync::{
		RwLock,
		atomic::{AtomicU64, Ordering},
	},
	time::{Duration, SystemTime},
};

use eyre::{Result, eyre};
use fuser::{FileAttr, FileHandle, FileType, Filesystem, FopenFlags, INodeNo};
use memmap2::MmapMut;
use tracing::{debug, error, info, instrument, warn};

use crate::sys::get_proc_info;

pub(crate) static FS_TTL: Duration = Duration::from_millis(500);
pub(crate) static FOXY_FH: u64 = 0xF057;

#[derive(Debug)]
pub(crate) struct File {
	pub attrs: FileAttr,
	pub path:  PathBuf,
	pub map:   MmapMut,
}

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct ProxySettings;

#[derive(Debug)]
pub(crate) struct FileProxy {
	pub handle:   FileHandle,
	pub backing:  File,
	pub cow:      Option<File>,
	pub dirty:    bool,
	pub open:     bool,
	pub pos:      u64,
	pub settings: ProxySettings,
}

static SYNTHETIC_INODE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct FoxyFs {
	proxies: RwLock<BTreeMap<INodeNo, FileProxy>>,
}

impl File {
	pub fn make_cow(&self, path: PathBuf) -> Result<Self> {
		let attrs = self.attrs;
		let map = unsafe {
			MmapMut::map_mut(
				&fs::OpenOptions::new()
					.read(true)
					.write(true)
					.create(true)
					.truncate(true)
					.open(&path)?,
			)?
		};

		Ok(Self { attrs, path, map })
	}

	pub fn new(path: PathBuf) -> Result<Self> {
		let metadata = path.metadata()?;

		let attrs = FileAttr {
			ino:     INodeNo(metadata.ino()),
			size:    metadata.size(),
			blocks:  metadata.blocks(),
			atime:   SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.atime().try_into()?),
			mtime:   SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.mtime().try_into()?),
			ctime:   SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.ctime().try_into()?),
			crtime:  metadata.created().unwrap_or(SystemTime::UNIX_EPOCH),
			kind:    FileType::RegularFile,
			perm:    metadata.permissions().mode().try_into()?,
			nlink:   metadata.nlink().try_into()?,
			uid:     metadata.uid(),
			gid:     metadata.gid(),
			rdev:    metadata.rdev().try_into()?,
			blksize: metadata.blksize().try_into()?,
			flags:   u32::MIN, // TODO(aki): Fix
		};

		let map = unsafe {
			MmapMut::map_mut(&fs::OpenOptions::new().read(true).write(true).open(&path)?)?
		};

		Ok(Self { attrs, path, map })
	}

	pub fn read(&mut self, offset: usize, size: usize) -> &[u8] {
		debug!("reading {} bytes from offset {}", size, offset);

		let size = std::cmp::min(size, self.attrs.size as usize);
		warn!("TODO: Smarter Read");
		&self.map[offset..size]
	}

	pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize> {
		debug!("writing {} bytes to offset {}", data.len(), offset);

		Ok(self.map.get_mut(offset..).unwrap().write(data)?)
	}

	pub fn flush(&mut self) -> Result<()> {
		Ok(self.map.flush()?)
	}

	pub fn getattr(&self) -> FileAttr {
		self.attrs
	}

	#[allow(clippy::too_many_arguments, reason = "Many optional attrs")]
	pub fn setattr(
		&mut self,
		mode: Option<u32>,
		uid: Option<u32>,
		gid: Option<u32>,
		size: Option<u64>,
		atime: Option<fuser::TimeOrNow>,
		mtime: Option<fuser::TimeOrNow>,
		ctime: Option<SystemTime>,
		crtime: Option<SystemTime>,
		chgtime: Option<SystemTime>,
		bkuptime: Option<SystemTime>,
		flags: Option<fuser::BsdFileFlags>,
	) -> FileAttr {
		warn!("TODO: setattrs");
		self.attrs
	}
}

impl FileProxy {
	fn _check(&self, fh: Option<FileHandle>) -> Result<()> {
		if !self.open {
			return Err(eyre!("Attempted operation on file that is not open"));
		}

		if let Some(fh) = fh &&
			fh != self.handle
		{
			return Err(eyre!(
				"Attempted operation with file handle {}, but we're {}",
				fh,
				self.handle
			));
		}

		Ok(())
	}

	pub fn new(
		backing: PathBuf,
		cow: Option<PathBuf>,
		settings: Option<ProxySettings>,
	) -> Result<Self> {
		let backing = File::new(backing)?;
		let cow = if let Some(cow) = cow {
			Some(backing.make_cow(cow)?)
		} else {
			None
		};

		Ok(Self {
			handle: FileHandle(backing.attrs.ino.0 ^ FOXY_FH),
			backing,
			cow,
			dirty: false,
			open: false,
			pos: u64::MIN,
			settings: settings.unwrap_or_default(),
		})
	}

	pub fn open(&mut self) -> Result<FileHandle> {
		if self.open {
			return Err(eyre!("Attempted to open an already open file"));
		}

		self.open = true;
		Ok(self.handle)
	}

	pub fn close(&mut self, fh: FileHandle, flush: bool) -> Result<()> {
		self._check(Some(fh))?;

		self.open = false;

		if flush {
			self.flush(fh)
		} else {
			Ok(())
		}
	}

	pub fn read(&mut self, fh: FileHandle, offset: usize, size: usize) -> Result<&[u8]> {
		self._check(Some(fh))?;

		Ok(
			if self.dirty &&
				let Some(cow) = &mut self.cow
			{
				cow.read(offset, size)
			} else {
				self.backing.read(offset, size)
			},
		)
	}

	pub fn write(&mut self, fh: FileHandle, offset: usize, data: &[u8]) -> Result<usize> {
		self._check(Some(fh))?;

		if let Some(cow) = &mut self.cow {
			if !self.dirty {
				info!("Instantiating CoW");
				cow.map.copy_from_slice(&self.backing.map);
			}
			self.dirty = true;
			cow.write(offset, data)
		} else {
			self.backing.write(offset, data)
		}
	}

	pub fn flush(&mut self, fh: FileHandle) -> Result<()> {
		self._check(Some(fh))?;

		if self.dirty &&
			let Some(cow) = &mut self.cow
		{
			cow.flush()
		} else {
			self.backing.flush()
		}
	}

	pub fn getattr(&self) -> FileAttr {
		if self.dirty &&
			let Some(cow) = &self.cow
		{
			cow.getattr()
		} else {
			self.backing.getattr()
		}
	}

	#[allow(clippy::too_many_arguments, reason = "Many optional attrs")]
	pub fn setattr(
		&mut self,
		mode: Option<u32>,
		uid: Option<u32>,
		gid: Option<u32>,
		size: Option<u64>,
		atime: Option<fuser::TimeOrNow>,
		mtime: Option<fuser::TimeOrNow>,
		ctime: Option<SystemTime>,
		_fh: Option<FileHandle>,
		crtime: Option<SystemTime>,
		chgtime: Option<SystemTime>,
		bkuptime: Option<SystemTime>,
		flags: Option<fuser::BsdFileFlags>,
	) -> Result<FileAttr> {
		Ok(
			if self.dirty &&
				let Some(cow) = &mut self.cow
			{
				cow.setattr(
					mode, uid, gid, size, atime, mtime, ctime, crtime, chgtime, bkuptime, flags,
				)
			} else {
				self.backing.setattr(
					mode, uid, gid, size, atime, mtime, ctime, crtime, chgtime, bkuptime, flags,
				)
			},
		)
	}
}

impl FoxyFs {
	pub fn new() -> Result<Self> {
		Ok(Self { proxies: RwLock::new(BTreeMap::new()) })
	}

	pub fn add_proxy(
		&self,
		backing: PathBuf,
		cow: Option<PathBuf>,
		settings: Option<ProxySettings>,
	) -> Result<()> {
		let inode = SYNTHETIC_INODE.fetch_add(1, Ordering::AcqRel);

		#[allow(clippy::unwrap_used, reason = "RwLock go brrr")]
		if self
			.proxies
			.write()
			.unwrap()
			.insert(INodeNo(inode), FileProxy::new(backing, cow, settings)?)
			.is_some()
		{
			return Err(eyre!("Already proxying inode {}", inode));
		}

		Ok(())
	}
}

impl Filesystem for FoxyFs {
	#[instrument(skip(self, req, _config), fields(process))]
	fn init(
		&mut self,
		req: &fuser::Request,
		_config: &mut fuser::KernelConfig,
	) -> std::io::Result<()> {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		Ok(())
	}

	#[instrument(skip(self))]
	fn destroy(&mut self) {}

	#[instrument(skip(self, req, reply), fields(process))]
	fn lookup(
		&self,
		req: &fuser::Request,
		parent: INodeNo,
		name: &std::ffi::OsStr,
		reply: fuser::ReplyEntry,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req))]
	fn forget(&self, req: &fuser::Request, ino: INodeNo, nlookup: u64) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn getattr(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: Option<FileHandle>,
		reply: fuser::ReplyAttr,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		#[allow(clippy::unwrap_used, reason = "RwLock go brrr")]
		if let Some(proxy) = self.proxies.write().unwrap().get_mut(&ino) {
			reply.attr(&FS_TTL, &proxy.getattr());
		} else {
			warn!("No file proxy for inode {ino}");
			reply.error(fuser::Errno::ENOENT);
		}
	}

	#[instrument(
		skip(
			self, req, mode, uid, gid, size, atime, mtime, ctime, crtime, chgtime, bkuptime, flags,
			reply
		),
		fields(process)
	)]
	fn setattr(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		mode: Option<u32>,
		uid: Option<u32>,
		gid: Option<u32>,
		size: Option<u64>,
		atime: Option<fuser::TimeOrNow>,
		mtime: Option<fuser::TimeOrNow>,
		ctime: Option<SystemTime>,
		fh: Option<FileHandle>,
		crtime: Option<SystemTime>,
		chgtime: Option<SystemTime>,
		bkuptime: Option<SystemTime>,
		flags: Option<fuser::BsdFileFlags>,
		reply: fuser::ReplyAttr,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		#[allow(clippy::unwrap_used, reason = "RwLock go brrr")]
		if let Some(proxy) = self.proxies.write().unwrap().get_mut(&ino) {
			match proxy.setattr(
				mode, uid, gid, size, atime, mtime, ctime, fh, crtime, chgtime, bkuptime, flags,
			) {
				Ok(attr) => reply.attr(&FS_TTL, &attr),
				Err(err) => {
					error!("{}", err);
					reply.error(fuser::Errno::EACCES);
				},
			}
		} else {
			warn!("No file proxy for inode {ino}");
			reply.error(fuser::Errno::ENOENT);
		}
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn readlink(&self, req: &fuser::Request, ino: INodeNo, reply: fuser::ReplyData) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn mknod(
		&self,
		req: &fuser::Request,
		parent: INodeNo,
		name: &std::ffi::OsStr,
		mode: u32,
		umask: u32,
		rdev: u32,
		reply: fuser::ReplyEntry,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn mkdir(
		&self,
		req: &fuser::Request,
		parent: INodeNo,
		name: &std::ffi::OsStr,
		mode: u32,
		umask: u32,
		reply: fuser::ReplyEntry,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn unlink(
		&self,
		req: &fuser::Request,
		parent: INodeNo,
		name: &std::ffi::OsStr,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn rmdir(
		&self,
		req: &fuser::Request,
		parent: INodeNo,
		name: &std::ffi::OsStr,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn symlink(
		&self,
		req: &fuser::Request,
		parent: INodeNo,
		link_name: &std::ffi::OsStr,
		target: &Path,
		reply: fuser::ReplyEntry,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::EPERM);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn rename(
		&self,
		req: &fuser::Request,
		parent: INodeNo,
		name: &std::ffi::OsStr,
		newparent: INodeNo,
		newname: &std::ffi::OsStr,
		flags: fuser::RenameFlags,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn link(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		newparent: INodeNo,
		newname: &std::ffi::OsStr,
		reply: fuser::ReplyEntry,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::EPERM);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn open(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		flags: fuser::OpenFlags,
		reply: fuser::ReplyOpen,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		#[allow(clippy::unwrap_used, reason = "RwLock go brrr")]
		if let Some(proxy) = self.proxies.write().unwrap().get_mut(&ino) {
			match proxy.open() {
				Ok(fh) => reply.opened(fh, FopenFlags::empty()),
				Err(err) => {
					error!("{}", err);
					reply.error(fuser::Errno::EACCES);
				},
			}
		} else {
			warn!("No file proxy for inode {ino}");
			reply.error(fuser::Errno::ENOENT);
		}
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn read(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		offset: u64,
		size: u32,
		flags: fuser::OpenFlags,
		lock_owner: Option<fuser::LockOwner>,
		reply: fuser::ReplyData,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		#[allow(clippy::unwrap_used, reason = "RwLock go brrr")]
		if let Some(proxy) = self.proxies.write().unwrap().get_mut(&ino) {
			match proxy.read(fh, offset as usize, size as usize) {
				Ok(data) => reply.data(data),
				Err(err) => {
					error!("{}", err);
					reply.error(fuser::Errno::EACCES);
				},
			}
		} else {
			warn!("No file proxy for inode {ino}");
			reply.error(fuser::Errno::ENOENT);
		}
	}

	#[instrument(skip(self, req, data, reply), fields(process))]
	fn write(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		offset: u64,
		data: &[u8],
		write_flags: fuser::WriteFlags,
		flags: fuser::OpenFlags,
		lock_owner: Option<fuser::LockOwner>,
		reply: fuser::ReplyWrite,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		#[allow(clippy::unwrap_used, reason = "RwLock go brrr")]
		if let Some(proxy) = self.proxies.write().unwrap().get_mut(&ino) {
			match proxy.write(fh, offset as usize, data) {
				Ok(written) => reply.written(written as u32),
				Err(err) => {
					error!("{}", err);
					reply.error(fuser::Errno::EACCES);
				},
			}
		} else {
			warn!("No file proxy for inode {ino}");
			reply.error(fuser::Errno::ENOENT);
		}
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn flush(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		lock_owner: fuser::LockOwner,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		#[allow(clippy::unwrap_used, reason = "RwLock go brrr")]
		if let Some(proxy) = self.proxies.write().unwrap().get_mut(&ino) {
			match proxy.flush(fh) {
				Ok(_) => reply.ok(),
				Err(err) => {
					error!("{}", err);
					reply.error(fuser::Errno::EACCES);
				},
			}
		} else {
			warn!("No file proxy for inode {ino}");
			reply.error(fuser::Errno::ENOENT);
		}
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn release(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		flags: fuser::OpenFlags,
		lock_owner: Option<fuser::LockOwner>,
		flush: bool,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		#[allow(clippy::unwrap_used, reason = "RwLock go brrr")]
		if let Some(proxy) = self.proxies.write().unwrap().get_mut(&ino) {
			match proxy.close(fh, flush) {
				Ok(_) => reply.ok(),
				Err(err) => {
					warn!("{}", err);
					reply.error(fuser::Errno::EACCES);
				},
			}
		} else {
			warn!("No file proxy for inode {ino}");
			reply.error(fuser::Errno::ENOENT);
		}
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn fsync(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		datasync: bool,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn opendir(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		flags: fuser::OpenFlags,
		reply: fuser::ReplyOpen,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn readdir(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		offset: u64,
		reply: fuser::ReplyDirectory,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn readdirplus(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		offset: u64,
		reply: fuser::ReplyDirectoryPlus,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn releasedir(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		flags: fuser::OpenFlags,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn fsyncdir(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		datasync: bool,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn statfs(&self, req: &fuser::Request, ino: INodeNo, reply: fuser::ReplyStatfs) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn setxattr(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		name: &std::ffi::OsStr,
		value: &[u8],
		flags: i32,
		position: u32,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn getxattr(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		name: &std::ffi::OsStr,
		size: u32,
		reply: fuser::ReplyXattr,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn listxattr(&self, req: &fuser::Request, ino: INodeNo, size: u32, reply: fuser::ReplyXattr) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn removexattr(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		name: &std::ffi::OsStr,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn access(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		mask: fuser::AccessFlags,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn create(
		&self,
		req: &fuser::Request,
		parent: INodeNo,
		name: &std::ffi::OsStr,
		mode: u32,
		umask: u32,
		flags: i32,
		reply: fuser::ReplyCreate,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn getlk(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		lock_owner: fuser::LockOwner,
		start: u64,
		end: u64,
		typ: i32,
		pid: u32,
		reply: fuser::ReplyLock,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn setlk(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		lock_owner: fuser::LockOwner,
		start: u64,
		end: u64,
		typ: i32,
		pid: u32,
		sleep: bool,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn bmap(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		blocksize: u32,
		idx: u64,
		reply: fuser::ReplyBmap,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn ioctl(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		flags: fuser::IoctlFlags,
		cmd: u32,
		in_data: &[u8],
		out_size: u32,
		reply: fuser::ReplyIoctl,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn poll(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		ph: fuser::PollNotifier,
		events: fuser::PollEvents,
		flags: fuser::PollFlags,
		reply: fuser::ReplyPoll,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn fallocate(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		offset: u64,
		length: u64,
		mode: i32,
		reply: fuser::ReplyEmpty,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn lseek(
		&self,
		req: &fuser::Request,
		ino: INodeNo,
		fh: FileHandle,
		offset: i64,
		whence: i32,
		reply: fuser::ReplyLseek,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}

	#[instrument(skip(self, req, reply), fields(process))]
	fn copy_file_range(
		&self,
		req: &fuser::Request,
		ino_in: INodeNo,
		fh_in: FileHandle,
		offset_in: u64,
		ino_out: INodeNo,
		fh_out: FileHandle,
		offset_out: u64,
		len: u64,
		flags: fuser::CopyFileRangeFlags,
		reply: fuser::ReplyWrite,
	) {
		let proc = get_proc_info(req.pid());
		tracing::Span::current().record("process", proc.map(|ref p| p.to_string()));

		warn!("Unimplemented");

		reply.error(fuser::Errno::ENOSYS);
	}
}
