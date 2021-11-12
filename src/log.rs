use std::{
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread::JoinHandle,
};

use serde::{Deserialize, Serialize};
use time::{format_description, OffsetDateTime};

use crate::{
    crypto::{self, PrivateKey, PublicKey},
    user::UserId,
};

const HASH_LEN_BITS: usize = 256;
const HASH_LEN_BYTES: usize = HASH_LEN_BITS / 8;

const MAGIC_HASH: &[u8; 32] = b"It is a hash of the first block.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Log {
    pub time: OffsetDateTime,
    pub user_id: UserId,
    pub msg: String,
    prev_hash: [u8; HASH_LEN_BYTES],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncLog {
    log: Vec<u8>,
    pub_key: PublicKey,
}

impl Log {
    pub fn new(user_id: UserId, msg: impl Into<String>) -> Self {
        let time = OffsetDateTime::now_utc();
        Self {
            time,
            user_id,
            msg: msg.into(),
            prev_hash: *MAGIC_HASH,
        }
    }

    pub fn encrypt(self, root_pub: &PublicKey) -> anyhow::Result<EncLog> {
        let (tmp_pri, tmp_pub) = crypto::gen_keypair();
        let message = tmp_pri.message_to(root_pub)?;

        let encoded = bincode::serialize(&self)?;
        let log = message.encrypt(encoded)?;

        Ok(EncLog {
            pub_key: tmp_pub,
            log,
        })
    }
}

impl EncLog {
    pub fn decrypt(self, root_pri: &PrivateKey) -> anyhow::Result<Log> {
        let message = root_pri.message_to(&self.pub_key)?;

        let decrypted = message.decrypt(self.log)?;
        bincode::deserialize(&decrypted).map_err(Into::into)
    }

    pub fn hash(&self) -> [u8; HASH_LEN_BYTES] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.log);
        hasher.update(b"::<> <>:: ::<>"); // turbofish, why not?
        hasher.update(self.pub_key.as_ref());
        hasher.finalize().into()
    }
}

#[derive(Debug)]
pub struct Logger {
    root_key: PublicKey,
    logs: Vec<EncLog>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncLogs(Vec<EncLog>);

#[derive(Debug)]
pub struct Logs(Vec<Log>);

impl std::fmt::Display for Logs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let time_format = format_description::parse(
            "[month repr:short] [day] [hour]:[minute]:[second].[subsecond digits:3]",
        )
        .unwrap();

        for log in &self.0 {
            let time = log.time.format(&time_format).map_err(|_| std::fmt::Error)?;

            writeln!(f, "{} (user_id={}) {}", time, log.user_id, log.msg)?;
        }

        Ok(())
    }
}

impl Logger {
    pub fn new(root_key: PublicKey) -> Self {
        Self {
            root_key,
            logs: Vec::new(),
        }
    }

    pub fn with_logs(root_key: PublicKey, logs: EncLogs) -> Self {
        Self {
            root_key,
            logs: logs.0,
        }
    }

    fn last_hash(&self) -> [u8; HASH_LEN_BYTES] {
        self.logs.last().map(EncLog::hash).unwrap_or(*MAGIC_HASH)
    }

    pub fn push(&mut self, mut log: Log) -> anyhow::Result<()> {
        log.prev_hash = self.last_hash();
        let enc = log.encrypt(&self.root_key)?;
        self.logs.push(enc);
        Ok(())
    }

    pub fn into_logs(self) -> EncLogs {
        EncLogs(self.logs)
    }
    pub fn logs(&self) -> EncLogs {
        EncLogs(self.logs.clone())
    }

    pub fn decrypt_logs(&self, root_pri: &PrivateKey) -> anyhow::Result<Logs> {
        Ok(Logs(
            self.logs
                .iter()
                .map(|log| log.clone().decrypt(root_pri))
                .collect::<Result<_, _>>()?,
        ))
    }

    pub fn into_receiver(self) -> (ArcLogger, LogReceiver, LogSender) {
        let arc_logger = Arc::new(Mutex::new(self));
        let (recv, sender) = LogReceiver::new(arc_logger.clone());
        (arc_logger, recv, sender)
    }
}

pub type ArcLogger = Arc<Mutex<Logger>>;
pub type LogSender = Sender<Log>;

pub struct LogReceiver {
    logger: ArcLogger,
    receiver: Receiver<Log>,
}

pub type LogHandler = JoinHandle<anyhow::Result<()>>;

impl LogReceiver {
    pub fn new(logger: ArcLogger) -> (Self, Sender<Log>) {
        let (sender, receiver) = mpsc::channel();
        (Self { logger, receiver }, sender)
    }

    pub fn start(self) -> LogHandler {
        std::thread::spawn(move || -> anyhow::Result<()> {
            while let Ok(log) = self.receiver.recv() {
                self.logger.lock().expect("locking the logger").push(log)?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let (root_pri, root_pub) = crypto::gen_keypair();

        let log = Log {
            time: OffsetDateTime::now_utc(),
            user_id: 0x17,
            msg: "access denied".into(),
            prev_hash: [0x77; 32],
        };

        let enc = log.clone().encrypt(&root_pub).unwrap();

        let dec = enc.decrypt(&root_pri).unwrap();

        assert_eq!(dec, log);
    }
}
