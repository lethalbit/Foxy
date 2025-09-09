// SPDX-License-Identifier: BSD-3-Clause

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime},
};

use clap::{Arg, ArgAction, Command};
use eyre::OptionExt;
use fuser::{FileAttr, FileType, Filesystem, MountOption};
use libc::{ENOSYS, EOF, EPERM};
use memmap2::MmapMut;
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
use tokio::sync::Mutex;
use tracing::{Level, debug, error, event, info, instrument, warn};
use tracing_subscriber::{
    Layer,
    filter::{EnvFilter, LevelFilter},
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

static SYS_INFO: OnceLock<Arc<Mutex<System>>> = OnceLock::new();

fn initialize_tracing(log_level: LevelFilter, json: bool) -> eyre::Result<()> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(log_level.into())
        .with_env_var("FOXY_LOG_LEVEL")
        .from_env_lossy()
        .add_directive("fuser=warn".parse()?);

    tracing_subscriber::registry()
        .with(cfg!(debug_assertions).then(|| {
            console_subscriber::spawn().with_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::ERROR.into())
                    .from_env_lossy()
                    .add_directive("tokio=trace".parse().unwrap())
                    .add_directive("runtime=trace".parse().unwrap()),
            )
        }))
        // XXX(aki): Lol, lmao even
        .with(json.then(|| fmt::layer().json().with_filter(env_filter.clone())))
        .with((!json).then(|| fmt::layer().compact().with_filter(env_filter)))
        .with(tracing_error::ErrorLayer::default())
        .init();
    Ok(())
}

#[derive(Debug)]
struct ProcInfo {
    pid: u32,
    exe: Option<PathBuf>,
    name: String,
}

struct FoxyFS<'a> {
    sys_info: Arc<Mutex<System>>,
    backing_attrs: FileAttr,
    backing_file: &'a Path,
    backing_map: MmapMut,
    dirty: bool,
    open: bool,
    seek: i64,
    cow_attrs: Option<FileAttr>,
    cow_file: Option<&'a Path>,
    cow_map: Option<MmapMut>,
}

impl<'a> Drop for FoxyFS<'a> {
    fn drop(&mut self) {}
}

static FS_TTL: Duration = Duration::from_millis(500);
static FOXY_FH: u64 = 0xCA7;

impl<'a> FoxyFS<'a> {
    pub fn new(file: &'a Path, cow: Option<&'a Path>) -> eyre::Result<Self> {
        let meta = file.metadata()?;

        let attrs = FileAttr {
            ino: meta.ino(),
            size: meta.size(),
            blocks: meta.blocks(),
            atime: SystemTime::UNIX_EPOCH + Duration::from_secs(meta.atime().try_into()?),
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(meta.mtime().try_into()?),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(meta.ctime().try_into()?),
            crtime: meta.created().unwrap_or(SystemTime::UNIX_EPOCH),
            kind: FileType::RegularFile,
            perm: meta.permissions().mode().try_into()?,
            nlink: meta.nlink().try_into()?,
            uid: meta.uid(),
            gid: meta.gid(),
            rdev: meta.rdev().try_into()?,
            blksize: meta.blksize().try_into()?,
            flags: u32::MIN,
        };

        let cow_map = if let Some(cow_file) = cow {
            Some(unsafe {
                MmapMut::map_mut(
                    &fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(cow_file)?,
                )?
            })
        } else {
            None
        };

        Ok(Self {
            sys_info: SYS_INFO.get().unwrap().clone(),
            backing_attrs: attrs,
            backing_file: file,
            backing_map: unsafe {
                MmapMut::map_mut(&fs::OpenOptions::new().read(true).write(true).open(file)?)?
            },
            dirty: false,
            open: false,
            seek: 0,
            cow_attrs: None,
            cow_file: cow,
            cow_map: cow_map,
        })
    }

    fn _get_proc(&mut self, raw_pid: u32) -> Option<ProcInfo> {
        if raw_pid == 0 {
            return None;
        }

        let mut info = self.sys_info.blocking_lock();
        let pid = Pid::from_u32(raw_pid);

        let proc = if let Some(proc) = info.process(pid) {
            Some(proc)
        } else {
            if info.refresh_processes_specifics(
                sysinfo::ProcessesToUpdate::Some(&[pid]),
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
            info.process(pid)
        };

        if let Some(proc) = proc {
            return Some(ProcInfo {
                pid: raw_pid,
                exe: proc.exe().map(|exe| {
                    let mut exe_path = PathBuf::new();
                    exe_path.push(exe);
                    exe_path
                }),
                name: String::from(proc.name().to_str()?),
            });
        }

        None
    }
}

impl Filesystem for FoxyFS<'_> {
    #[instrument(skip_all)]
    fn lookup(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        event!(Level::DEBUG, parent, ?name, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip(self, req))]
    fn forget(&mut self, req: &fuser::Request<'_>, ino: u64, nlookup: u64) {
        event!(Level::DEBUG, ino, proc = ?self._get_proc(req.pid()));
    }

    #[instrument(skip_all)]
    fn getattr(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: Option<u64>,
        reply: fuser::ReplyAttr,
    ) {
        event!(Level::INFO, ino, fh, proc = ?self._get_proc(req.pid()));
        reply.attr(&FS_TTL, &self.backing_attrs);
    }

    #[instrument(skip_all)]
    fn setattr(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<u64>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<u32>,
        reply: fuser::ReplyAttr,
    ) {
        event!(
            Level::INFO,
            ino, mode, uid, gid, size, ?atime, ?mtime, ?ctime, fh, ?crtime, ?chgtime, ?bkuptime, flags, proc = ?self._get_proc(req.pid())
        );

        warn!("TODO: Not Implemented");

        reply.attr(&FS_TTL, &self.backing_attrs);
    }

    #[instrument(skip_all)]
    fn readlink(&mut self, req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyData) {
        event!(Level::DEBUG, ino, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn mknod(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: fuser::ReplyEntry,
    ) {
        event!(Level::DEBUG, parent, ?name, mode, umask, rdev, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn mkdir(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        event!(Level::DEBUG, parent, ?name, mode, umask, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn unlink(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::DEBUG, parent, ?name, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn rmdir(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::DEBUG, parent, ?name, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn symlink(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        link_name: &std::ffi::OsStr,
        target: &Path,
        reply: fuser::ReplyEntry,
    ) {
        event!(Level::DEBUG, parent, ?link_name, ?target, proc = ?self._get_proc(req.pid()));
        reply.error(EPERM);
    }

    #[instrument(skip_all)]
    fn rename(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        newparent: u64,
        newname: &std::ffi::OsStr,
        flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::DEBUG, parent, ?name, newparent, ?newname, flags, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn link(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        event!(Level::DEBUG, ino, newparent, ?newname, proc = ?self._get_proc(req.pid()));
        reply.error(EPERM);
    }

    #[instrument(skip_all)]
    fn open(&mut self, req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
        event!(Level::INFO, ino, flags, proc = ?self._get_proc(req.pid()));

        // "Open" the file
        self.open = true;

        reply.opened(FOXY_FH, 0);
    }

    #[instrument(skip_all)]
    fn read(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        event!(Level::INFO, ino, fh, offset, size, flags, lock_owner, proc = ?self._get_proc(req.pid()));

        if !self.open || fh != FOXY_FH {
            warn!(
                "Attempted read when file is not open or with wrong file handle (open: {}, handle: {})",
                self.open, fh
            );
            reply.error(ENOSYS);
            return;
        }

        let offset: usize = offset.try_into().unwrap();
        let size: usize = std::cmp::min(
            size.try_into().unwrap(),
            (if let Some(attrs) = self.cow_attrs {
                attrs.size
            } else {
                self.backing_attrs.size
            })
            .try_into()
            .unwrap(),
        );

        // If we're dirty, and we have CoW backing, then use that for any read requests
        let data = if self.dirty
            && let Some(cow) = &self.cow_map
        {
            &cow[offset..size]
        } else {
            &self.backing_map[offset..size]
        };

        info!("Returning {} bytes of data to {}", data.len(), req.pid());

        reply.data(data);
    }

    #[instrument(skip_all)]
    fn write(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        write_flags: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        event!(Level::INFO, ino, fh, offset, data, write_flags, flags, lock_owner, proc = ?self._get_proc(req.pid()));

        if !self.open || fh != FOXY_FH {
            warn!(
                "Attempted write when file is not open or with wrong file handle (open: {}, handle: {})",
                self.open, fh
            );
            reply.error(ENOSYS);
            return;
        }

        // If we have CoW backing, then write to that
        if let Some(cow) = &mut self.cow_map {
            // If this is the first write, first copy of the contents of the backing file to the CoW
            if !self.dirty {
                info!("Instantiating CoW");
                cow.copy_from_slice(&self.backing_map);
            }

            warn!("TODO: CoW Not Implemented");

            info!("Marking us dirty");
            self.dirty = true;
        }

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn flush(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::INFO, ino, fh, lock_owner, proc = ?self._get_proc(req.pid()));

        if !self.open || fh != FOXY_FH {
            warn!(
                "Attempted flush when file is not open or with wrong file handle (open: {}, handle: {})",
                self.open, fh
            );
            reply.error(ENOSYS);
            return;
        }

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn release(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        flags: i32,
        lock_owner: Option<u64>,
        flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::INFO, ino, fh, flags, lock_owner, flush, proc = ?self._get_proc(req.pid()));

        if !self.open || fh != FOXY_FH {
            warn!(
                "Attempted release when file is not open or with wrong file handle (open: {}, handle: {})",
                self.open, fh
            );
            reply.error(ENOSYS);
            return;
        }

        info!("Closing file");
        self.open = false;

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn fsync(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::INFO, ino, fh, datasync, proc = ?self._get_proc(req.pid()));

        if !self.open || fh != FOXY_FH {
            warn!(
                "Attempted fsync when file is not open or with wrong file handle (open: {}, handle: {})",
                self.open, fh
            );
            reply.error(ENOSYS);
            return;
        }

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn opendir(&mut self, req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
        event!(Level::DEBUG, ino, flags, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn readdir(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectory,
    ) {
        event!(Level::DEBUG, ino, fh, offset, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn readdirplus(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectoryPlus,
    ) {
        event!(Level::DEBUG, ino, fh, offset, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn releasedir(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::DEBUG, ino, fh, flags, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn fsyncdir(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::DEBUG, ino, fh, datasync, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn statfs(&mut self, req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyStatfs) {
        event!(Level::DEBUG, ino, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn setxattr(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        name: &std::ffi::OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::INFO, ino, ?name, value, flags, position, proc = ?self._get_proc(req.pid()));

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn getxattr(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        name: &std::ffi::OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        event!(Level::INFO, ino, ?name, size, proc = ?self._get_proc(req.pid()));

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn listxattr(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        event!(Level::INFO, ino, size, proc = ?self._get_proc(req.pid()));

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn removexattr(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::INFO, ino, ?name, proc = ?self._get_proc(req.pid()));

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn access(&mut self, req: &fuser::Request<'_>, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        event!(Level::INFO, ino, mask, proc = ?self._get_proc(req.pid()));
        // Yeah, sure, everyone can access it, why not
        reply.ok();
    }

    #[instrument(skip_all)]
    fn create(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        event!(Level::DEBUG, parent, ?name, mode, umask, flags, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn getlk(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        reply: fuser::ReplyLock,
    ) {
        event!(Level::INFO, ino, fh, lock_owner, start, end, typ, pid, proc = ?self._get_proc(req.pid()));

        if !self.open || fh != FOXY_FH {
            warn!(
                "Attempted get lock when file is not open or with wrong file handle (open: {}, handle: {})",
                self.open, fh
            );
            reply.error(ENOSYS);
            return;
        }

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn setlk(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::INFO, ino, fh, lock_owner, start, end, typ, pid, sleep, proc = ?self._get_proc(req.pid()));

        if !self.open || fh != FOXY_FH {
            warn!(
                "Attempted set lock when file is not open or with wrong file handle (open: {}, handle: {})",
                self.open, fh
            );
            reply.error(ENOSYS);
            return;
        }

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn bmap(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        blocksize: u32,
        idx: u64,
        reply: fuser::ReplyBmap,
    ) {
        event!(Level::DEBUG, ino, blocksize, idx, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn ioctl(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        flags: u32,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: fuser::ReplyIoctl,
    ) {
        event!(Level::DEBUG, ino, fh, flags, cmd, in_data, out_size, proc = ?self._get_proc(req.pid()));

        warn!("ioctl???");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn fallocate(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: fuser::ReplyEmpty,
    ) {
        event!(Level::INFO, ino, fh, offset, length, mode, proc = ?self._get_proc(req.pid()));

        if !self.open || fh != FOXY_FH {
            warn!(
                "Attempted fallocate when file is not open or with wrong file handle (open: {}, handle: {})",
                self.open, fh
            );
            reply.error(ENOSYS);
            return;
        }

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn lseek(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        whence: i32,
        reply: fuser::ReplyLseek,
    ) {
        event!(Level::INFO, ino, fh, offset, whence, proc = ?self._get_proc(req.pid()));

        if !self.open || fh != FOXY_FH {
            warn!(
                "Attempted lseek when file is not open or with wrong file handle (open: {}, handle: {})",
                self.open, fh
            );
            reply.error(ENOSYS);
            return;
        }

        warn!("TODO: Not Implemented");

        reply.error(ENOSYS);
    }

    #[instrument(skip_all)]
    fn copy_file_range(
        &mut self,
        req: &fuser::Request<'_>,
        ino_in: u64,
        fh_in: u64,
        offset_in: i64,
        ino_out: u64,
        fh_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
        reply: fuser::ReplyWrite,
    ) {
        event!(Level::DEBUG, ino_in, fh_in, offset_in, ino_out, fh_out, offset_out, len, flags, proc = ?self._get_proc(req.pid()));
        reply.error(ENOSYS);
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;

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
            Arg::new("json")
                .short('j')
                .action(ArgAction::SetTrue)
                .help("Enable JSON output"),
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
        .arg(Arg::new("cow").short('c').help("Set a backing COW file"))
        .get_matches();

    initialize_tracing(
        {
            match cmd.get_count("verbose") {
                0 => LevelFilter::INFO,
                1 => LevelFilter::DEBUG,
                _ => LevelFilter::TRACE,
            }
        },
        cmd.get_flag("json"),
    )?;

    let mountpoint = cmd
        .get_one::<String>("FILE_MOUNT")
        .ok_or_eyre("Unable to get FILE_MOUNT")?
        .clone();

    let mut backing = PathBuf::new();
    backing.push(
        cmd.get_one::<String>("TARGET_FILE")
            .ok_or_eyre("Unable to get TARGET_FILE")?
            .clone(),
    );

    // XXX(aki): This is hacky but shut up
    let _ = (!backing.exists())
        .then_some(0)
        .ok_or_eyre("Backing file does not exist");

    info!("Proxy target: {}", mountpoint);
    info!("Backing file: {:?}", backing);

    let cow = if let Some(cow_file) = cmd.get_one::<String>("cow") {
        let mut cow = PathBuf::new();
        cow.push(cow_file);

        info!("CoW file: {:?}", cow);

        Some(cow)
    } else {
        warn!("No CoW file specified, write-through enabled");

        None
    };

    let fuse_options = vec![
        MountOption::AllowOther,
        MountOption::FSName("FOXY".to_string()),
        MountOption::AutoUnmount,
    ];

    let _ = SYS_INFO.get_or_init(|| {
        Arc::new(Mutex::new(System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
        )))
    });

    tokio::task::spawn_blocking(move || {
        fuser::mount2(
            FoxyFS::new(backing.as_path(), cow.as_deref()).unwrap(),
            mountpoint,
            &fuse_options,
        )
        .unwrap();
    })
    .await?;

    Ok(())
}
