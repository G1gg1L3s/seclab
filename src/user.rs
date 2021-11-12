use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::crypto::{self, EncryptedPrivateKey, PrivateKey, PublicKey};

const MAX_USER_COUNT: usize = 16;

pub const READ: u8 = 0b001;
pub const WRITE: u8 = 0b010;
pub const EXEC: u8 = 0b100;

const MASK: u8 = READ | WRITE | EXEC;
#[derive(Clone, Copy, Default, Serialize, Deserialize)]
pub struct Permissions(u8);

impl std::fmt::Debug for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Permissions(")?;
        let mut sep = "";

        for (mask, name) in [(READ, "READ"), (WRITE, "WRITE"), (EXEC, "EXEC")] {
            if self.0 & mask > 0 {
                write!(f, "{}{}", sep, name)?;
                sep = " | ";
            }
        }
        write!(f, ")")
    }
}

impl Permissions {
    pub fn new(perm: u8) -> Self {
        Self(perm & MASK)
    }

    pub fn is_read(&self) -> bool {
        self.0 & READ > 0
    }

    pub fn is_write(&self) -> bool {
        self.0 & WRITE > 0
    }

    pub fn is_exec(&self) -> bool {
        self.0 & EXEC > 0
    }
    pub fn set_read(&mut self) {
        self.0 |= READ;
    }

    pub fn set_write(&mut self) {
        self.0 |= WRITE;
    }

    pub fn set_exec(&mut self) {
        self.0 |= EXEC;
    }

    pub fn clear_read(&mut self) {
        self.0 &= !READ;
    }

    pub fn clear_write(&mut self) {
        self.0 &= !WRITE;
    }

    pub fn clear_exec(&mut self) {
        self.0 &= !EXEC;
    }

    pub fn to_unix(&self) -> u16 {
        const UNIX_READ: u16 = 0o400;
        const UNIX_WRITE: u16 = 0o200;
        const UNIX_EXEC: u16 = 0o100;

        let mut perm = 0;
        if self.is_read() {
            perm |= UNIX_READ;
        }
        if self.is_write() {
            perm |= UNIX_WRITE;
        }
        if self.is_exec() {
            perm |= UNIX_EXEC;
        }

        perm
    }

    pub fn and(&self, mask: u8) -> bool {
        self.0 & mask > 0
    }

    pub fn add(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

pub type Username = String;

// TODO: fix debug
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    id: UserId,
    username: Username,
    pass_hash: String,
    private_key: EncryptedPrivateKey,
    public_key: PublicKey,
    locked: bool,
}

const MIN_PASS_LEN: usize = 6;

fn validate_password(pass: &str) -> anyhow::Result<()> {
    if pass.len() <= MIN_PASS_LEN {
        anyhow::bail!("password is too short");
    }
    let score = zxcvbn::zxcvbn(pass, &[])?.score();
    if score < 3 {
        anyhow::bail!("password is too weak")
    } else {
        Ok(())
    }
}

impl User {
    pub fn new(id: UserId, username: Username, password: &str) -> anyhow::Result<Self> {
        let (private_key, public_key) = crypto::gen_keypair();
        let private_key = private_key.encrypt(password)?;
        let pass_hash = crypto::new_password_hash(password)?;
        Ok(Self {
            id,
            username,
            pass_hash,
            private_key,
            public_key,
            locked: false,
        })
    }

    pub fn check_pass(&self, pass: &str) -> anyhow::Result<()> {
        crypto::verify_password(&self.pass_hash, pass)
    }

    pub fn set_pass(&mut self, old_pass: &str, pass: &str) -> anyhow::Result<()> {
        validate_password(pass)?;
        let pass_hash = crypto::new_password_hash(pass)?;
        self.pass_hash = pass_hash;
        let private_key = self.private_key.clone().decrypt(old_pass)?;
        self.private_key = private_key.encrypt(pass)?;
        Ok(())
    }
}

pub type UserId = u64;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UserManager {
    user_ctr: UserId,
    usernames: HashMap<String, UserId>,
    users: HashMap<UserId, User>,
}

impl UserManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_user(&mut self, username: Username, password: String) -> anyhow::Result<UserId> {
        if self.users.len() == MAX_USER_COUNT {
            anyhow::bail!("Max number of users is already registered");
        }

        if self.usernames.get(&username).is_some() {
            anyhow::bail!("the user already exists")
        }
        let id = self.user_ctr;
        self.user_ctr += 1;
        let user = User::new(id, username.clone(), &password)?;
        self.usernames.insert(username, id);
        self.users.insert(id, user);
        Ok(id)
    }

    pub fn login(&self, username: &str, password: &str) -> anyhow::Result<(UserId, PrivateKey)> {
        if let Some(uid) = self.usernames.get(username).copied() {
            self.login_with_uid(uid, password)
        } else {
            anyhow::bail!("Wrong username or password")
        }
    }

    pub fn login_with_uid(
        &self,
        uid: UserId,
        password: &str,
    ) -> anyhow::Result<(UserId, PrivateKey)> {
        if let Some(user) = self.users.get(&uid) {
            if user.locked {
                anyhow::bail!("User is locker. Contact root to unlock the account")
            }
            if user.check_pass(password).is_ok() {
                let key = user.private_key.clone().decrypt(password)?;
                return Ok((user.id, key));
            }
        }
        anyhow::bail!("Wrong username or password")
    }

    pub fn get_id_for(&self, user: &str) -> Option<UserId> {
        self.usernames.get(user).copied()
    }

    // TODO: probably should accept uid
    pub fn get_public_key_for(&self, user: &str) -> Option<&PublicKey> {
        self.usernames
            .get(user)
            .and_then(|id| self.users.get(id).map(|user| &user.public_key))
    }

    pub fn unlock(&mut self, user: &str) -> anyhow::Result<()> {
        let doesnt_exist = || anyhow::anyhow!("User doesn't exist");

        let uid = self.usernames.get(user).ok_or_else(doesnt_exist)?;
        let user = self.users.get_mut(uid).ok_or_else(doesnt_exist)?;
        user.locked = false;
        Ok(())
    }

    pub fn lock(&mut self, uid: UserId) -> anyhow::Result<()> {
        let doesnt_exist = || anyhow::anyhow!("User doesn't exist");

        let user = self.users.get_mut(&uid).ok_or_else(doesnt_exist)?;
        user.locked = true;
        Ok(())
    }

    pub fn set_pass(&mut self, uid: UserId, old_pass: &str, pass: &str) -> anyhow::Result<()> {
        let user = self
            .users
            .get_mut(&uid)
            .ok_or_else(|| anyhow::anyhow!("user not found"))?;

        user.set_pass(old_pass, pass)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_checks() {
        let perm = Permissions::new(READ | WRITE);

        assert!(perm.is_read());
        assert!(perm.is_write());
        assert!(!perm.is_exec());
    }

    #[test]
    fn test_set() {
        let mut perm = Permissions::new(0);

        assert!(!perm.is_read());
        assert!(!perm.is_write());
        assert!(!perm.is_exec());

        perm.set_read();
        perm.set_write();
        perm.set_exec();

        assert!(perm.is_read());
        assert!(perm.is_write());
        assert!(perm.is_exec());
    }

    #[test]
    fn test_clear() {
        let mut perm = Permissions::new(READ | WRITE | EXEC);

        assert!(perm.is_read());
        assert!(perm.is_write());
        assert!(perm.is_exec());

        perm.clear_read();
        perm.clear_write();
        perm.clear_exec();

        assert!(!perm.is_read());
        assert!(!perm.is_write());
        assert!(!perm.is_exec());
    }
}
