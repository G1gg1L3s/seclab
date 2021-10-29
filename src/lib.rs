use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use fs::{Fs, FsSession};
use serde::{Deserialize, Serialize};
use user::{UserId, UserManager};

use crate::user::Permissions;

pub mod fs;
pub mod user;

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemImage {
    users: UserManager,
    fs: Fs,
}

impl SystemImage {
    pub fn unpack(self) -> System {
        System {
            users: self.users,
            fs: Arc::new(Mutex::new(self.fs)),
        }
    }
}

pub struct System {
    users: UserManager,
    fs: Arc<Mutex<Fs>>,
}

pub struct SystemSession {
    sys: System,
    user_id: UserId,
    root_id: UserId,
}

impl Default for System {
    fn default() -> Self {
        Self::new()
    }
}

impl System {
    pub fn login(
        self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<(SystemSession, FsSession)> {
        let user_id = self.users.login(username, password)?;

        let fs = Arc::clone(&self.fs);
        let fs = FsSession::new(user_id, fs);
        let root_id = self.users.get_id_for("root").expect("root should exists");
        let sys = SystemSession {
            sys: self,
            user_id,
            root_id,
        };

        Ok((sys, fs))
    }

    pub fn new() -> Self {
        let mut users = UserManager::new();
        let root_id = users.new_user("root".into(), "".into()).expect("no users");
        Self {
            users,
            fs: Arc::new(Mutex::new(Fs::new(root_id))),
        }
    }
}

impl System {
    pub fn pack(self) -> Result<SystemImage, Self> {
        match Arc::try_unwrap(self.fs) {
            Ok(fs) => Ok(SystemImage {
                users: self.users,
                fs: fs.into_inner().expect("no one is holding a mutex"),
            }),
            Err(fs) => Err(Self {
                users: self.users,
                fs,
            }),
        }
    }
}

impl SystemSession {
    pub fn logout(self) -> System {
        self.sys
    }

    pub fn useradd(&mut self, username: String) -> anyhow::Result<()> {
        if self.user_id == self.root_id {
            self.sys.users.new_user(username, "".into())?;
            Ok(())
        } else {
            anyhow::bail!("only the root can add new users")
        }
    }

    pub fn add_perm(&mut self, user: &str, perm: &str, path: &str) -> anyhow::Result<()> {
        if self.user_id != self.root_id {
            anyhow::bail!("Only root can change permissions")
        }

        let uid = self
            .sys
            .users
            .get_id_for(user)
            .ok_or_else(|| anyhow!("User not found"))?;

        let perm = perm
            .chars()
            .map(|c| match c {
                'r' => user::READ,
                'w' => user::WRITE,
                'e' => user::EXEC,
                _ => 0,
            })
            .reduce(|prev, next| prev | next)
            .unwrap_or(0);

        let mut fs = self.sys.fs.lock().expect("acquiring lock");

        let ino = fs.resolve_path(path)?;
        fs.add_perm(ino, uid, Permissions::new(perm))?;
        Ok(())
    }
}
