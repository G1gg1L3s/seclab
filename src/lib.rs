use std::{
    collections::HashMap,
    convert::TryInto,
    ffi::{OsStr, OsString},
    time::{Duration, SystemTime},
};

use fuser::{ReplyCreate, Request};
use libc::{EISDIR, ENOENT, ENOSYS, ENOTDIR};

pub type Id = u64;

pub enum InodeKind {
    Regular { content: Vec<u8> },
    Dir { list: HashMap<OsString, Id> },
}

impl InodeKind {
    fn from_mode(mode: u32) -> Option<Self> {
        let mode = libc::S_IFMT as u32 & mode;
        match mode {
            m if m == libc::S_IFREG as u32 => Some(Self::Regular {
                content: Default::default(),
            }),
            m if m == libc::S_IFDIR as u32 => Some(Self::Dir {
                list: Default::default(),
            }),
            _ => None,
        }
    }

    fn as_regular(&self) -> Option<&Vec<u8>> {
        if let InodeKind::Regular { content } = self {
            Some(content)
        } else {
            None
        }
    }

    fn as_dir(&self) -> Option<&HashMap<OsString, Id>> {
        if let InodeKind::Dir { list } = self {
            Some(list)
        } else {
            None
        }
    }

    fn as_regular_mut(&mut self) -> Option<&mut Vec<u8>> {
        if let InodeKind::Regular { content } = self {
            Some(content)
        } else {
            None
        }
    }

    fn as_dir_mut(&mut self) -> Option<&mut HashMap<OsString, Id>> {
        if let InodeKind::Dir { list } = self {
            Some(list)
        } else {
            None
        }
    }

    fn fuse_kind(&self) -> fuser::FileType {
        match self {
            InodeKind::Regular { .. } => fuser::FileType::RegularFile,
            InodeKind::Dir { .. } => fuser::FileType::Directory,
        }
    }
}

pub struct InodeAttr {
    ino: Id,
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
    crtime: SystemTime,
    perm: u16,
}

pub struct Inode {
    kind: InodeKind,
    attr: InodeAttr,
}

impl Inode {
    fn fuser_attr(&self) -> fuser::FileAttr {
        let size = self.kind.as_regular().map(Vec::len).unwrap_or(0) as u64;

        fuser::FileAttr {
            ino: self.attr.ino,
            size,
            blocks: 1,
            atime: self.attr.atime,
            mtime: self.attr.mtime,
            ctime: self.attr.ctime,
            crtime: self.attr.crtime,
            kind: self.kind.fuse_kind(),
            perm: self.attr.perm,
            nlink: 1,
            uid: 1,
            gid: 1,
            rdev: 1,
            blksize: 4096,
            flags: 0,
        }
    }
}

pub struct Fs {
    inodes: HashMap<Id, Inode>,
    inode_ctr: u64,
}

impl Fs {
    fn lookup_name(&self, parent: u64, name: &OsStr) -> Result<&Inode, i32> {
        let parent = self.inodes.get(&parent).ok_or(ENOENT)?;
        let dir = parent.kind.as_dir().ok_or(ENOTDIR)?;
        let id = dir.get(name).ok_or(ENOENT)?;
        self.inodes.get(id).ok_or(ENOENT)
    }

    fn read(&self, ino: u64, _offset: i64, _size: u32, _flags: i32) -> Result<&[u8], i32> {
        let file = self.inodes.get(&ino).ok_or(ENOENT)?;
        let content = file.kind.as_regular().ok_or(EISDIR)?;
        Ok(content)
    }
    fn read_dir(&self, ino: u64, _fh: u64, _offset: i64) -> Result<&HashMap<OsString, Id>, i32> {
        let file = self.inodes.get(&ino).ok_or(ENOENT)?;
        file.kind.as_dir().ok_or(libc::ENOTDIR)
    }

    fn get_inode(&self, inode: &Id) -> Result<&Inode, i32> {
        self.inodes.get(inode).ok_or(ENOENT)
    }

    fn get_inode_mut(&mut self, inode: &Id) -> Result<&mut Inode, i32> {
        self.inodes.get_mut(inode).ok_or(ENOENT)
    }

    pub fn new_test() -> Self {
        let mut inodes = HashMap::new();
        let mut root_dir = HashMap::new();
        root_dir.insert(".".into(), 1);
        root_dir.insert("file".into(), 2);
        inodes.insert(
            1,
            Inode {
                kind: InodeKind::Dir { list: root_dir },

                attr: InodeAttr {
                    ino: 1,
                    atime: SystemTime::now(),
                    mtime: SystemTime::now(),
                    ctime: SystemTime::now(),
                    crtime: SystemTime::now(),
                    perm: 0o644,
                },
            },
        );
        inodes.insert(
            2,
            Inode {
                kind: InodeKind::Regular {
                    content: b"hello\n".to_vec(),
                },
                attr: InodeAttr {
                    ino: 2,
                    atime: SystemTime::now(),
                    mtime: SystemTime::now(),
                    ctime: SystemTime::now(),
                    crtime: SystemTime::now(),
                    perm: 0o644,
                },
            },
        );
        Self {
            inodes,
            inode_ctr: 3,
        }
    }

    fn write(&mut self, ino: u64, offset: i64, data: &[u8]) -> Result<u32, i32> {
        let offset: usize = offset.try_into().map_err(|_| libc::EFAULT)?;
        let inode = self.get_inode_mut(&ino)?;

        // TODO: dedicated method
        let file = inode.kind.as_regular_mut().ok_or(EISDIR)?;

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

    fn create(&mut self, parent: u64, name: &OsStr, mode: u32, flags: i32) -> Result<&Inode, i32> {
        if self.lookup_name(parent, name).is_ok() {
            return Err(libc::EEXIST);
        }

        #[allow(unused_variables)]
        let (read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => (true, false),
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(libc::EINVAL);
            }
        };

        let mut kind = InodeKind::from_mode(mode).ok_or(ENOSYS)?;

        let perm = match kind {
            InodeKind::Regular { .. } => 0o666,
            InodeKind::Dir { .. } => 0o777,
        };

        let ino = self.alloc_inode();
        let attr = InodeAttr {
            ino,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            perm,
        };

        if let Some(dir) = kind.as_dir_mut() {
            dir.insert(".".into(), ino);
            dir.insert("..".into(), parent);
        }

        let inode = Inode { kind, attr };

        self.inodes.insert(ino, inode);
        let parent = self.get_inode_mut(&parent).expect("already checked");
        let dirs = parent.kind.as_dir_mut().expect("already checked");
        dirs.insert(name.to_owned(), ino);

        Ok(self.get_inode(&ino).expect("just inserted"))
    }

    fn set_attr(&mut self, ino: u64, size: Option<u64>) -> Result<&Inode, i32> {
        if let Some(new_size) = size {
            let inode = self.get_inode_mut(&ino)?;
            let file = inode.kind.as_regular_mut().ok_or(EISDIR)?;

            let new_len: usize = new_size.try_into().expect("sorry");
            file.resize(new_len, 0);
            Ok(inode)
        } else {
            unreachable!("sorry, you are not supposed to reach here")
        }
    }
}

impl fuser::Filesystem for Fs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: fuser::ReplyEntry) {
        log::debug!("LOOKUP parent={}, name={:?}", parent, name);

        match self.lookup_name(parent, name) {
            Ok(inode) => reply.entry(&Duration::new(0, 0), &inode.fuser_attr(), 0),
            Err(err) => reply.error(err),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        log::debug!("READ ino={}, offset={}, size={}", ino, offset, size);

        match Self::read(self, ino, offset, size, flags) {
            Ok(data) => reply.data(data),
            Err(err) => reply.error(err),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        log::debug!("READDIR ino={}, fh={}, offset={}", ino, fh, offset);

        let files = match self.read_dir(ino, fh, offset) {
            Ok(files) => files,
            Err(err) => {
                reply.error(err);
                return;
            }
        };

        for (i, (name, id)) in files.iter().enumerate().skip(offset as usize) {
            let inode = match self.get_inode(id) {
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
    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        if let Err(err) = self.get_inode(&ino) {
            reply.error(err)
        } else {
            reply.opened(0, 0)
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        match self.get_inode(&ino) {
            Ok(inode) => reply.attr(&Duration::new(0, 0), &inode.fuser_attr()),
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
        match self.write(ino, offset, data) {
            Ok(size) => reply.written(size),
            Err(err) => reply.error(err),
        }
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
        log::debug!(
            "CREATE (parent: {:#x?}, name: {:?}, mode: {}, umask: {:#x?}, \
            flags: {:#x?})",
            parent,
            name,
            mode,
            _umask,
            flags
        );

        match self.create(parent, name, mode, flags) {
            Ok(inode) => reply.created(&Duration::new(0, 0), &inode.fuser_attr(), 0, 0, 0),
            Err(err) => reply.error(err),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
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
        log::debug!("SETATTR:");
        log::debug!("\tino={:?}:", ino);
        log::debug!("\tmode={:?}:", mode);
        log::debug!("\tuid={:?}:", uid);
        log::debug!("\tgid={:?}:", gid);
        log::debug!("\tsize={:?}:", size);
        log::debug!("\tatime={:?}:", atime);
        log::debug!("\tmtime={:?}:", mtime);
        log::debug!("\tctime={:?}:", ctime);
        log::debug!("\tfh={:?}:", fh);
        log::debug!("\tcrtime={:?}:", crtime);
        log::debug!("\tchgtime={:?}:", chgtime);
        log::debug!("\tbkuptime={:?}:", bkuptime);
        log::debug!("\tflags={:?}:", flags);

        if mode.is_some()
            || uid.is_some()
            || gid.is_some()
            || atime.is_some()
            || mtime.is_some()
            || ctime.is_some()
            || fh.is_some()
            || crtime.is_some()
            || chgtime.is_some()
            || bkuptime.is_some()
            || flags.is_some()
        {
            reply.error(libc::ENOTSUP);
            return;
        }

        match self.set_attr(ino, size) {
            Ok(inode) => reply.attr(&Duration::new(0, 0), &inode.fuser_attr()),
            Err(err) => reply.error(err),
        }
    }
}
