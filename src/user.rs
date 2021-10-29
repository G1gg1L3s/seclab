use std::collections::HashMap;

pub const READ: u8 = 0b001;
pub const WRITE: u8 = 0b010;
pub const EXEC: u8 = 0b100;

const MASK: u8 = READ | WRITE | EXEC;
#[derive(Clone, Copy, Default)]
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
}

pub type Username = String;

// TODO: fix debug
#[derive(Debug)]
pub struct User {
    id: UserId,
    username: Username,
    // TODO: change because it's insecure
    password: String,
}

impl User {
    pub fn new(id: UserId, username: Username, password: String) -> Self {
        Self {
            id,
            username,
            password,
        }
    }

    pub fn check_pass(&self, pass: &str) -> bool {
        // TODO: insecure
        self.password == pass
    }
}

pub type UserId = u64;

#[derive(Default)]
pub struct UserManager {
    user_ctr: UserId,
    users: HashMap<Username, User>,
}

impl UserManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_user(&mut self, username: Username, password: String) -> anyhow::Result<()> {
        if self.users.get(&username).is_some() {
            anyhow::bail!("the user already exists")
        }
        let id = self.user_ctr;
        self.user_ctr += 1;
        let user = User {
            id,
            username: username.clone(),
            password,
        };
        self.users.insert(username, user);
        Ok(())
    }

    pub fn login(&self, username: &str, password: &str) -> bool {
        self.users
            .get(username)
            .map(|user| user.check_pass(password))
            .unwrap_or(false)
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
