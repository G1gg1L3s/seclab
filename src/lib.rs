use std::ffi::OsString;

use fs::Fs;
use fuser::BackgroundSession;
use serde::{Deserialize, Serialize};
use user::UserManager;

pub mod fs;
pub mod user;

pub struct SystemSession {
    users: UserManager,
    fs: fs::FsSession,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct System {
    users: UserManager,
    fs: Fs,
}

impl Default for System {
    fn default() -> Self {
        Self::new()
    }
}

impl System {
    pub fn login(self, username: &str, password: &str) -> anyhow::Result<SystemSession> {
        let user_id = self.users.login(username, password)?;

        let fs = self.fs.login(user_id);
        Ok(SystemSession {
            users: self.users,
            fs,
        })
    }

    pub fn new() -> Self {
        let mut users = UserManager::new();
        let root_id = users.new_user("root".into(), "".into()).expect("no users");
        Self {
            users,
            fs: Fs::new(root_id),
        }
    }
}

impl SystemSession {
    pub fn logout(self) -> System {
        let fs = self.fs.logout();
        System {
            users: self.users,
            fs,
        }
    }

    pub fn run(self, mountpoint: &str) -> anyhow::Result<BackgroundSession> {
        let name: OsString = "fsname=seclab".into();
        let auto_unmount: OsString = "auto_unmount".into();

        fuser::spawn_mount(self.fs, mountpoint, &[&name, &auto_unmount]).map_err(Into::into)
    }
}
