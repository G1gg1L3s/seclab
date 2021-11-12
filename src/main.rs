use std::{
    io::{stdout, ErrorKind, Write},
    time::Duration,
};

use futures::executor::block_on;
use seclab::{System, SystemImage, SystemSession};
use structopt::StructOpt;

const PASSWORD_TRIES: usize = 3;

#[derive(StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "tmp")]
    mountpoint: String,

    #[structopt(short, long)]
    image: String,

    #[structopt(short, long)]
    debug: bool,

    #[structopt(short, long, default_value = "60")]
    timeout: u64,
}

fn fix_newline(str: &mut String) {
    if str.ends_with('\n') {
        str.pop();
        if str.ends_with('\r') {
            str.pop();
        }
    }
}

fn read_credentials() -> anyhow::Result<(String, String)> {
    print!("Username: ");
    std::io::stdout().flush()?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    fix_newline(&mut username);
    let password = read_password("Password")?;
    Ok((username, password))
}

fn read_password(prefix: &str) -> anyhow::Result<String> {
    print!("{}: ", prefix);
    std::io::stdout().flush()?;
    rpassword::read_password().map_err(Into::into)
}

enum ShellRes {
    Timeout,
    Exit,
}

async fn start_shell(timeout: Duration, sys: &mut SystemSession) -> ShellRes {
    let f = async_std::io::timeout(timeout, async {
        let mut line = String::new();

        loop {
            print!("> ");
            stdout().flush().unwrap();
            async_std::io::stdin().read_line(&mut line).await.unwrap();
            let exit = exec_cmd(sys, &line);
            line.clear();
            if exit {
                return Ok(());
            }
        }
    })
    .await;

    match f {
        Ok(()) => ShellRes::Exit,
        Err(_) => {
            println!("timeout: you need to login again");
            ShellRes::Timeout
        }
    }
}

fn exec_cmd(sys: &mut SystemSession, line: &str) -> bool {
    let cmd = line.split_whitespace().collect::<Vec<_>>();

    let res = match cmd.as_slice() {
        [] => return false,
        ["exit"] => return true,
        ["useradd", name] => sys.useradd(name.to_string()),
        ["permadd", user, perm, path] => sys.add_perm(user, perm, path),
        ["logs"] => sys.logs().map(|logs| print!("{}", logs)),
        ["unlock", name] => sys.unlock(name),
        ["chpass"] => chpass(sys),
        [cmd, ..] => Err(anyhow::anyhow!("Unknown command: {}", cmd)),
    };

    if let Err(err) = res {
        println!("Error: {}", err);
    }
    false
}

fn chpass(sys: &mut SystemSession) -> anyhow::Result<()> {
    let actual_pass = read_password("Enter current password")?;
    let new_pass = read_password("Enter new password")?;
    let new_pass_again = read_password("Enter new password again")?;
    if new_pass != new_pass_again {
        anyhow::bail!("password don't match");
    }

    sys.chpass(&actual_pass, &new_pass)
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();

    if let Err(err) = std::fs::create_dir(&opt.mountpoint) {
        match err.kind() {
            ErrorKind::AlreadyExists => {}
            _ => anyhow::bail!("creating the directory: {}", err),
        }
    };

    let system = match std::fs::File::open(&opt.image) {
        Ok(file) => {
            let img: SystemImage = bincode::deserialize_from(file)?;
            img.unpack()?
        }
        Err(err) if err.kind() == ErrorKind::NotFound => System::new(),
        Err(err) => return Err(err.into()),
    };

    let (username, password) = read_credentials()?;

    let (mut sys, fs) = system.login(&username, &password)?;

    if opt.debug {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();
    }

    let handler = fs.run(&opt.mountpoint)?;
    let timeout = Duration::new(opt.timeout, 0);

    'outer: loop {
        // Default timeout, for which if user is innactive, system is logouting
        let innactive_timeout: Duration = Duration::new(60, 0);

        let result = block_on(start_shell(timeout, &mut sys));
        if let ShellRes::Exit = result {
            break 'outer;
        }
        let fs = sys.get_fs();
        let locker = fs.lock().expect("error locking the fs");

        match locker.elapsed() {
            Ok(duration) if duration < innactive_timeout => {}
            _ => {
                println!("logouting due to inactivity");
                sys.log("logouting due to inactivity");
                break 'outer;
            }
        }

        let mut counter = 0;
        loop {
            let pass = read_password("Enter password again")?;
            match sys.validate_password(&pass) {
                Ok(_) => continue 'outer,
                Err(err) => {
                    println!("[{}/{}]: Error: {}", counter + 1, PASSWORD_TRIES, err);
                    counter += 1
                }
            }

            if counter == PASSWORD_TRIES {
                println!("{} incorrect password attempts, locking", counter);
                sys.lock()?;
                break 'outer;
            }
        }
    }

    handler.join();

    let image = match sys.logout().pack() {
        seclab::PackResult::Ok(image) => image,
        seclab::PackResult::Err(err) => return Err(err),
        seclab::PackResult::UnwrapErr(_) => unreachable!("there are no other threads"),
    };
    let file = std::fs::File::create(opt.image)?;
    bincode::serialize_into(file, &image)?;

    Ok(())
}
