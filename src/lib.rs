use std::sync::{Arc, Mutex};

use crate::log::{ArcLogger, EncLogs, LogHandler, LogSender, Logger};
use anyhow::anyhow;
use crypto::{PrivateKey, PublicKey};
use fs::{Fs, FsImage, FsSession};
use serde::{Deserialize, Serialize};
use user::{UserId, UserManager};
use utils::{InspectErr, SendLog};

use crate::user::Permissions;

pub mod crypto;
pub mod fs;
pub mod log;
pub mod user;
pub mod utils;

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemImage {
    users: UserManager,
    fs: FsImage,
    logs: EncLogs,
}

impl SystemImage {
    pub fn unpack(self) -> anyhow::Result<System> {
        let root_key = self
            .users
            .get_public_key_for("root")
            .expect("root should exist")
            .to_owned();
        let (logger, log_recv, log_sender) =
            Logger::with_logs(root_key.clone(), self.logs).into_receiver();
        let log_handler = log_recv.start();

        Ok(System {
            users: self.users,
            fs: Arc::new(Mutex::new(self.fs.unpack(log_sender.clone()))),
            log_handler,
            root_key,
            logger,
            log_sender,
        })
    }
}

pub struct System {
    users: UserManager,
    fs: Arc<Mutex<Fs>>,
    root_key: PublicKey,
    log_handler: LogHandler,
    logger: ArcLogger,
    log_sender: LogSender,
}

pub struct SystemSession {
    sys: System,
    user_id: UserId,
    root_id: UserId,
    user_key: PrivateKey,
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
        let (user_id, user_key) = self.users.login(username, password).inspect_err(|err| {
            self.log_sender.send_log(
                0,
                format!("login failed with username={} |> {:?}", username, err),
            );
        })?;

        self.log_sender.send_log(user_id, "new login");

        let fs = Arc::clone(&self.fs);
        let fs = FsSession::new(user_id, fs);
        let root_id = self.users.get_id_for("root").expect("root should exists");
        let sys = SystemSession {
            sys: self,
            user_id,
            root_id,
            user_key,
        };

        Ok((sys, fs))
    }

    pub fn new() -> Self {
        let mut users = UserManager::new();
        let root_id = users.new_user("root".into(), "".into()).expect("no users");
        let root_key = users.get_public_key_for("root").unwrap().to_owned();

        let (logger, logrecv, log_sender) = Logger::new(root_key.clone()).into_receiver();
        let log_handler = logrecv.start();

        Self {
            users,
            fs: Arc::new(Mutex::new(Fs::new(root_id, log_sender.clone()))),
            log_handler,
            root_key,
            logger,
            log_sender,
        }
    }
}

pub enum PackResult {
    Ok(SystemImage),
    Err(anyhow::Error),
    UnwrapErr(System),
}

fn explicit_drop<T>(_t: T) {}

impl System {
    pub fn pack(self) -> PackResult {
        match Arc::try_unwrap(self.fs) {
            Ok(fs) => {
                // It's important to destroy the filesystem first, so it drops the
                // log sender, which would unblock the logger
                let fs = fs
                    .into_inner()
                    .expect("no one is holding the mutext")
                    .pack();

                // Explicitly destroy the log sender, which would unblock the logger
                explicit_drop(self.log_sender);
                let logs = match self.log_handler.join().expect("log thread panicked") {
                    Ok(_) => self.logger.lock().expect("locking the logger").logs(),
                    Err(err) => return PackResult::Err(err),
                };

                PackResult::Ok(SystemImage {
                    users: self.users,
                    fs,
                    logs,
                })
            }
            Err(fs) => PackResult::UnwrapErr(Self {
                users: self.users,
                fs,
                log_handler: self.log_handler,
                root_key: self.root_key,
                logger: self.logger,
                log_sender: self.log_sender,
            }),
        }
    }
}

impl SystemSession {
    pub fn logout(self) -> System {
        self.sys.log_sender.send_log(self.user_id, "logout");
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

    pub fn logs(&self) -> anyhow::Result<String> {
        if self.user_id != self.root_id {
            anyhow::bail!("Only root can view the logs")
        }

        let logs = self
            .sys
            .logger
            .lock()
            .expect("locking the logger")
            .decrypt_logs(&self.user_key)?;

        Ok(logs.to_string())
    }
}
