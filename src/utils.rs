use crate::{log::LogSender, user::UserId};

pub trait InspectErr<E> {
    fn inspect_err(self, f: impl FnOnce(&E)) -> Self;
}

impl<T, E> InspectErr<E> for Result<T, E> {
    fn inspect_err(self, f: impl FnOnce(&E)) -> Self {
        if let Err(err) = &self {
            f(err)
        }
        self
    }
}

pub trait SendLog {
    fn send_log(&self, uid: UserId, msg: impl Into<String>);
}

impl SendLog for LogSender {
    fn send_log(&self, uid: UserId, msg: impl Into<String>) {
        self.send(crate::log::Log::new(uid, msg))
            .expect("error sending the log")
    }
}
