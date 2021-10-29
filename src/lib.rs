pub mod fs;
pub mod user;

pub struct System {
    users: user::UserManager,
    fs: fs::FsSession,
}

impl System {}
