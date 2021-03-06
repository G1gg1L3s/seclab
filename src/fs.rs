use std::{
    collections::HashMap,
    convert::TryInto,
    ffi::{OsStr, OsString},
    fmt::{Debug, Display},
    path::{Component, Path},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, SystemTimeError},
};

use anyhow::anyhow;
use fuser::{BackgroundSession, ReplyCreate, Request, TimeOrNow};
use libc::{EACCES, EEXIST, EFAULT, EINVAL, EISDIR, ENOENT, ENOSYS, ENOTDIR, ENOTSUP};
use nix::errno::Errno;
use serde::{Deserialize, Serialize};

use crate::{
    log::LogSender,
    user::{Permissions, UserId, EXEC, READ, WRITE},
};

const TTL: Duration = Duration::ZERO;

pub type Id = u64;

enum InodeKindTag {
    Regular,
    Dir,
}

impl From<InodeKindTag> for InodeKind {
    fn from(tag: InodeKindTag) -> Self {
        match tag {
            InodeKindTag::Regular => Self::Regular {
                content: Default::default(),
            },
            InodeKindTag::Dir => Self::Dir {
                list: Default::default(),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum InodeKind {
    Regular { content: Vec<u8> },
    Dir { list: HashMap<OsString, Id> },
}

impl InodeKind {
    fn as_regular(&self) -> Result<&[u8], i32> {
        if let InodeKind::Regular { content } = self {
            Ok(content)
        } else {
            Err(EISDIR)
        }
    }

    fn as_dir(&self) -> Result<&HashMap<OsString, Id>, i32> {
        if let InodeKind::Dir { list } = self {
            Ok(list)
        } else {
            Err(ENOTDIR)
        }
    }

    fn as_regular_mut(&mut self) -> Result<&mut Vec<u8>, i32> {
        if let InodeKind::Regular { content } = self {
            Ok(content)
        } else {
            Err(EISDIR)
        }
    }

    fn as_dir_mut(&mut self) -> Result<&mut HashMap<OsString, Id>, i32> {
        if let InodeKind::Dir { list } = self {
            Ok(list)
        } else {
            Err(ENOTDIR)
        }
    }

    fn fuse_kind(&self) -> fuser::FileType {
        match self {
            InodeKind::Regular { .. } => fuser::FileType::RegularFile,
            InodeKind::Dir { .. } => fuser::FileType::Directory,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InodeAttr {
    ino: Id,
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
    crtime: SystemTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Inode {
    kind: InodeKind,
    attr: InodeAttr,
    perm: HashMap<UserId, Permissions>,
}

impl Inode {
    fn fuser_attr(&self, user_id: UserId) -> fuser::FileAttr {
        let size = self.kind.as_regular().map(|x| x.len()).unwrap_or(0) as u64;

        let perm = self
            .perm
            .get(&user_id)
            .copied()
            .unwrap_or_default()
            .to_unix();

        fuser::FileAttr {
            ino: self.attr.ino,
            size,
            blocks: 1,
            atime: self.attr.atime,
            mtime: self.attr.mtime,
            ctime: self.attr.ctime,
            crtime: self.attr.crtime,
            kind: self.kind.fuse_kind(),
            perm,
            nlink: 1,
            uid: 1,
            gid: 1,
            rdev: 1,
            blksize: 4096,
            flags: 0,
        }
    }

    fn allowed(&self, user_id: UserId, mask: u8) -> bool {
        let perm = self.perm.get(&user_id).copied().unwrap_or_default();

        perm.and(mask)
    }

    fn new(tag: InodeKindTag, ino: Id, parent: Id, uid: UserId) -> Self {
        let attr = InodeAttr {
            ino,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
        };

        let mut kind = InodeKind::from(tag);

        if let Ok(dir) = kind.as_dir_mut() {
            dir.insert(".".into(), ino);
            dir.insert("..".into(), parent);
        }

        let mut perm = HashMap::new();
        let mask = match &kind {
            InodeKind::Regular { .. } => READ | WRITE,
            InodeKind::Dir { .. } => READ | WRITE | EXEC,
        };
        perm.insert(uid, Permissions::new(mask));

        Inode { kind, attr, perm }
    }
}

#[derive(Debug)]
pub struct Fs {
    inodes: HashMap<Id, Inode>,
    inode_ctr: u64,
    logger: LogSender,
    last_access: SystemTime,
}

impl FsImage {
    pub fn unpack(self, logger: LogSender) -> Fs {
        let Self { inode_ctr, inodes } = self;
        Fs {
            inodes,
            inode_ctr,
            logger,
            last_access: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsImage {
    inodes: HashMap<Id, Inode>,
    inode_ctr: u64,
}

pub struct FsSession {
    user_id: UserId,
    fs: Arc<Mutex<Fs>>,
}

impl Fs {
    pub fn new(root_id: UserId, logger: LogSender) -> Self {
        let inode = 1;
        let root = Inode::new(InodeKindTag::Dir, inode, root_id, root_id);
        let mut inodes = HashMap::new();
        inodes.insert(inode, root);

        Self {
            inode_ctr: 2,
            inodes,
            logger,
            last_access: SystemTime::now(),
        }
    }

    pub fn pack(self) -> FsImage {
        let Self {
            inodes,
            inode_ctr,
            logger: _,
            last_access: _,
        } = self;
        FsImage { inodes, inode_ctr }
    }

    fn lookup_name_secure(&self, uid: UserId, parent: u64, name: &OsStr) -> Result<&Inode, i32> {
        let parent = self.get_inode_secure(uid, &parent, READ)?;
        let dir = parent.kind.as_dir()?;
        let id = dir.get(name).ok_or(ENOENT)?;
        self.inodes.get(id).ok_or(ENOENT)
    }

    fn read(&self, uid: UserId, ino: u64, offset: i64, size: u32) -> Result<&[u8], i32> {
        let file = self.get_inode_secure(uid, &ino, READ)?;
        let content = file.kind.as_regular()?;

        let start: usize = offset
            .clamp(0, content.len() as i64)
            .try_into()
            .expect("sorry, 32 bit usize is not supported");

        let end = (start + size as usize).clamp(start, content.len());

        Ok(&content[start..end])
    }

    fn read_dir(&self, uid: UserId, ino: u64) -> Result<&HashMap<OsString, Id>, i32> {
        let file = self.get_inode_secure(uid, &ino, READ)?;
        file.kind.as_dir()
    }

    fn get_inode(&self, inode: &Id) -> Result<&Inode, i32> {
        self.inodes.get(inode).ok_or(ENOENT)
    }

    fn get_inode_secure(&self, uid: UserId, inode: &Id, mask: u8) -> Result<&Inode, i32> {
        let inode = self.inodes.get(inode).ok_or(ENOENT)?;
        if inode.allowed(uid, mask) {
            Ok(inode)
        } else {
            Err(EACCES)
        }
    }

    fn get_inode_mut(&mut self, inode: &Id) -> Result<&mut Inode, i32> {
        self.inodes.get_mut(inode).ok_or(ENOENT)
    }

    fn get_inode_mut_secure(
        &mut self,
        uid: UserId,
        inode: &Id,
        mask: u8,
    ) -> Result<&mut Inode, i32> {
        let inode = self.inodes.get_mut(inode).ok_or(ENOENT)?;
        if inode.allowed(uid, mask) {
            Ok(inode)
        } else {
            Err(EACCES)
        }
    }

    fn write(&mut self, uid: UserId, ino: u64, offset: i64, data: &[u8]) -> Result<u32, i32> {
        let inode = self.get_inode_mut_secure(uid, &ino, WRITE)?;
        let file = inode.kind.as_regular_mut()?;

        let offset: usize = offset.try_into().map_err(|_| EFAULT)?;
        let new_len = file.len().max(offset) + data.len();

        file.resize(new_len, 0);
        file[offset..][..data.len()].copy_from_slice(data);
        let written = data
            .len()
            .try_into()
            .expect("data is guaranteed to fit into 32 bits");
        Ok(written)
    }

    fn alloc_inode(&mut self) -> Id {
        let id = self.inode_ctr;
        self.inode_ctr += 1;
        id
    }

    fn create(&mut self, uid: UserId, parent: u64, name: &OsStr, mode: u32) -> Result<&Inode, i32> {
        let parent_inode = self.get_inode_mut_secure(uid, &parent, WRITE)?;

        let dir = parent_inode.kind.as_dir()?;
        if dir.get(name).is_some() {
            return Err(EEXIST);
        }

        let tag = {
            let mode = libc::S_IFMT as u32 & mode;

            match mode {
                libc::S_IFREG => InodeKindTag::Regular,
                libc::S_IFDIR => InodeKindTag::Dir,

                _ => return Err(ENOSYS),
            }
        };

        let ino = self.alloc_inode();
        let inode = Inode::new(tag, ino, parent, uid);

        self.inodes.insert(ino, inode);
        let parent = self.get_inode_mut(&parent).expect("already checked");
        let dirs = parent.kind.as_dir_mut().expect("already checked");
        dirs.insert(name.to_owned(), ino);

        Ok(self.get_inode(&ino).expect("just inserted"))
    }

    fn set_attr(
        &mut self,
        uid: UserId,
        ino: u64,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        crtime: Option<SystemTime>,
    ) -> Result<&Inode, i32> {
        fn unwrap_time(time: TimeOrNow) -> SystemTime {
            match time {
                TimeOrNow::SpecificTime(time) => time,
                TimeOrNow::Now => SystemTime::now(),
            }
        }

        let inode = self.get_inode_mut_secure(uid, &ino, WRITE)?;

        if let Some(new_size) = size {
            let file = inode.kind.as_regular_mut()?;
            let new_len: usize = new_size.try_into().expect("sorry");
            file.resize(new_len, 0);
        } else if let Some(mtime) = mtime {
            inode.attr.mtime = unwrap_time(mtime);
        } else if let Some(atime) = atime {
            inode.attr.atime = unwrap_time(atime);
        } else if let Some(ctime) = ctime {
            inode.attr.ctime = ctime;
        } else if let Some(crtime) = crtime {
            inode.attr.crtime = crtime;
        } else {
            unreachable!("sorry, you are not supposed to reach here")
        }

        Ok(inode)
    }

    fn remove(&mut self, uid: UserId, parent: u64, name: &OsStr) -> Result<(), i32> {
        let parent = self.get_inode_mut_secure(uid, &parent, READ | WRITE)?;
        let list = parent.kind.as_dir_mut()?;

        let file = list.remove(name).ok_or(ENOENT)?;

        self.inodes.remove(&file);
        // TODO: check kind of removed file
        Ok(())
    }

    fn check_access(&self, uid: UserId, ino: u64, mask: u8) -> Result<(), i32> {
        let inode = self.get_inode(&ino)?;

        if mask == 0 || inode.allowed(uid, mask) {
            Ok(())
        } else {
            Err(EACCES)
        }
    }

    pub fn resolve_path(&self, path: &str) -> anyhow::Result<Id> {
        let segments = Path::new(path).components();

        let mut parent = self.get_inode(&1).expect("where is the root");
        for segment in segments {
            let name = match segment {
                Component::Normal(x) => x,
                Component::RootDir | Component::CurDir | Component::ParentDir => OsStr::new("."),
                _ => anyhow::bail!("unsupported path structure"),
            };
            let dir = parent
                .kind
                .as_dir()
                .map_err(|_| anyhow!("file is not a directory"))?;
            let ino = dir.get(name).ok_or_else(|| anyhow!("file not found"))?;
            parent = self.get_inode(ino).map_err(|_| anyhow!("file not found"))?;
        }
        Ok(parent.attr.ino)
    }

    pub fn add_perm(&mut self, ino: u64, uid: UserId, perm: Permissions) -> anyhow::Result<()> {
        let inode = self
            .get_inode_mut(&ino)
            .map_err(|_| anyhow!("file not found"))?;
        inode.perm.entry(uid).or_default().add(perm);
        Ok(())
    }

    pub fn elapsed(&self) -> Result<Duration, SystemTimeError> {
        self.last_access.elapsed()
    }
}

impl FsSession {
    pub fn new(user_id: UserId, fs: Arc<Mutex<Fs>>) -> Self {
        Self { user_id, fs }
    }

    fn lock(&self) -> MutexGuard<Fs> {
        self.fs.lock().expect("acquiring lock")
    }

    pub fn run(self, mountpoint: &str) -> anyhow::Result<BackgroundSession> {
        let name: OsString = "fsname=seclab".into();
        let auto_unmount: OsString = "auto_unmount".into();

        fuser::spawn_mount(self, mountpoint, &[&name, &auto_unmount]).map_err(Into::into)
    }
}

macro_rules! log_fs {
    ($fs: expr, $uid: expr, $($arg: tt) *) => {
        $fs.logger.send(crate::log::Log::new($uid, format!($($arg)*))).expect("can't send the log")
    };
}

impl fuser::Filesystem for FsSession {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: fuser::ReplyEntry) {
        let fs = self.lock();

        let res = match fs.lookup_name_secure(self.user_id, parent, name) {
            Ok(inode) => {
                reply.entry(&TTL, &inode.fuser_attr(self.user_id), 0);
                format!("Ok(inode={})", inode.attr.ino)
            }
            Err(err) => {
                reply.error(err);
                format!("Err({})", Errno::from_i32(err))
            }
        };

        log_fs!(
            fs,
            self.user_id,
            "LOOKUP parent={}, name={:?} |> {}",
            parent,
            name,
            res
        );
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        let fs = self.lock();
        let res = match fs.read(self.user_id, ino, offset, size) {
            Ok(data) => {
                reply.data(data);
                format!("Ok(read={})", data.len())
            }
            Err(err) => {
                reply.error(err);
                format!("Err({})", Errno::from_i32(err))
            }
        };

        log_fs!(
            fs,
            self.user_id,
            "READ ino={}, offset={}, size={} |> {}",
            ino,
            offset,
            size,
            res
        );
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        let fs = self.lock();
        let files = match fs.read_dir(self.user_id, ino) {
            Ok(files) => files,
            Err(err) => {
                reply.error(err);
                return;
            }
        };

        for (i, (name, id)) in files.iter().enumerate().skip(offset as usize) {
            let inode = match fs.get_inode(id) {
                Ok(inode) => inode,
                Err(_) => continue,
            };
            let full = reply.add(inode.attr.ino, (i + 1) as i64, inode.kind.fuse_kind(), name);

            if full {
                break;
            }
        }
        reply.ok()
    }
    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
        let fs = self.lock();
        let res = match fs.get_inode(&ino) {
            Ok(inode) => {
                let mask = match flags & libc::O_ACCMODE {
                    libc::O_RDONLY => READ,
                    libc::O_WRONLY => WRITE,
                    libc::O_RDWR => READ | WRITE,
                    _ => {
                        return reply.error(EINVAL);
                    }
                };

                if inode.allowed(self.user_id, mask) {
                    reply.opened(0, 0);
                    "Ok(opened)".to_string()
                } else {
                    reply.error(EACCES);
                    Errno::from_i32(EACCES).to_string()
                }
            }
            Err(err) => {
                reply.error(err);
                format!("Err({})", Errno::from_i32(err))
            }
        };

        log_fs!(
            fs,
            self.user_id,
            "OPEN ino={}, flags={:x} |> {}",
            ino,
            flags,
            res
        );
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        match self.lock().get_inode_secure(self.user_id, &ino, READ) {
            Ok(inode) => reply.attr(&TTL, &inode.fuser_attr(self.user_id)),
            Err(err) => reply.error(err),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        let mut fs = self.lock();
        let res = match fs.write(self.user_id, ino, offset, data) {
            Ok(size) => {
                reply.written(size);
                format!("Ok(written={})", size)
            }
            Err(err) => {
                reply.error(err);
                format!("Err({})", Errno::from_i32(err))
            }
        };

        log_fs!(
            fs,
            self.user_id,
            "WRITE ino={}, offset={}, size={} |> {}",
            ino,
            offset,
            data.len(),
            res
        );
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let user_id = self.user_id;
        let mut fs = self.lock();

        let res = match fs.create(self.user_id, parent, name, mode) {
            Ok(inode) => {
                reply.created(&TTL, &inode.fuser_attr(user_id), 0, 0, 0);
                format!("Ok(ino={})", inode.attr.ino)
            }
            Err(err) => {
                reply.error(err);
                format!("Err({})", Errno::from_i32(err))
            }
        };

        log_fs!(
            fs,
            user_id,
            "CREATE parent={}, name={:?}, mode={:o}, flags={:x} |> {}",
            parent,
            name,
            mode,
            flags,
            res
        );
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<u64>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<u32>,
        reply: fuser::ReplyAttr,
    ) {
        use std::fmt::Write;

        let mut log = format!(
            "SETTATTR ino={}{}{}{}{}{:?}{:?}{:?}{}{:?}{:?}{:?}{}",
            ino,
            DisplayIfSome("mode", &mode),
            DisplayIfSome("uid", &uid),
            DisplayIfSome("gid", &gid),
            DisplayIfSome("size", &size),
            DisplayIfSome("atime", &atime),
            DisplayIfSome("mtime", &mtime),
            DisplayIfSome("ctime", &ctime),
            DisplayIfSome("fh", &fh),
            DisplayIfSome("crtime", &crtime),
            DisplayIfSome("chgtime", &chgtime),
            DisplayIfSome("bkuptime", &bkuptime),
            DisplayIfSome("flags", &flags),
        );

        let user_id = self.user_id;
        let mut fs = self.lock();
        let res = if mode.is_some()
            || uid.is_some()
            || gid.is_some()
            || fh.is_some()
            || chgtime.is_some()
            || bkuptime.is_some()
            || flags.is_some()
        {
            reply.error(ENOTSUP);
            format!("Err({})", Errno::from_i32(ENOTSUP))
        } else {
            match fs.set_attr(self.user_id, ino, size, atime, mtime, ctime, crtime) {
                Ok(inode) => {
                    reply.attr(&TTL, &inode.fuser_attr(user_id));
                    "Ok()".to_string()
                }
                Err(err) => {
                    reply.error(err);
                    format!("Err({})", Errno::from_i32(err))
                }
            }
        };

        write!(log, " |> {}", res).unwrap();

        log_fs!(fs, user_id, "{}", log);
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        let user_id = self.user_id;
        let mode = mode | libc::S_IFDIR;
        let mut fs = self.lock();
        let res = match fs.create(self.user_id, parent, name, mode) {
            Ok(inode) => {
                reply.entry(&TTL, &inode.fuser_attr(user_id), 0);
                format!("Ok(ino={})", inode.attr.ino)
            }
            Err(err) => {
                reply.error(err);
                format!("Err({})", Errno::from_i32(err))
            }
        };

        log_fs!(
            fs,
            user_id,
            "MKDIR parent={}, name={:?}, mode={:x} |> {}",
            parent,
            name,
            mode,
            res
        );
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let mut fs = self.lock();
        let res = match fs.remove(self.user_id, parent, name) {
            Ok(_) => {
                reply.ok();
                "Ok()".to_string()
            }
            Err(err) => {
                reply.error(err);
                format!("Err({})", Errno::from_i32(err))
            }
        };

        log_fs!(
            fs,
            self.user_id,
            "UNLINK parent={}, name={:?} |> {}",
            parent,
            name,
            res
        );
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let mut fs = self.lock();
        let res = match fs.remove(self.user_id, parent, name) {
            Ok(_) => {
                reply.ok();
                "Ok()".to_string()
            }
            Err(err) => {
                reply.error(err);
                format!("Err({})", Errno::from_i32(err))
            }
        };

        log_fs!(
            fs,
            self.user_id,
            "RMDIR parent={}, name={:?} |> {}",
            parent,
            name,
            res
        );
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        let sieve_mask = |m: i32, ret: u8| {
            if m & mask > 0 {
                ret
            } else {
                0
            }
        };

        let mask = sieve_mask(libc::R_OK, READ)
            | sieve_mask(libc::W_OK, WRITE)
            | sieve_mask(libc::X_OK, EXEC);

        let fs = self.lock();

        let res = match fs.check_access(self.user_id, ino, mask) {
            Ok(_) => {
                reply.ok();
                "Ok()".to_string()
            }
            Err(err) => {
                reply.error(err);
                format!("Err({})", Errno::from_i32(err))
            }
        };

        log::debug!("ACCESS ino={} mask={:o} |> {}", ino, mask, res);
    }
}

struct DisplayIfSome<'a, N, T>(N, &'a Option<T>);

impl<'a, N, T> std::fmt::Debug for DisplayIfSome<'a, N, T>
where
    N: Display,
    T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(t) = &self.1 {
            write!(f, " {}={:?}", self.0, t)
        } else {
            Ok(())
        }
    }
}

impl<'a, N, T> Display for DisplayIfSome<'a, N, T>
where
    N: Display,
    T: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(t) = &self.1 {
            write!(f, " {}={}", self.0, t)
        } else {
            Ok(())
        }
    }
}
