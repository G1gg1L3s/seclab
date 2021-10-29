use std::sync::{Arc, Mutex};

use fs::{Fs, FsSession};
use serde::{Deserialize, Serialize};
use user::UserManager;

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

impl Default for System {
    fn default() -> Self {
        Self::new()
    }
}

impl System {
    pub fn login(&self, username: &str, password: &str) -> anyhow::Result<FsSession> {
        let user_id = self.users.login(username, password)?;

        let fs = self.fs.clone();

        Ok(FsSession::new(user_id, fs))
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
