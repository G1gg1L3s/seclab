use std::io::{ErrorKind, Write};

use seclab::{System, SystemImage, SystemSession};
use shrust::{ExecError, Shell, ShellIO};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "tmp")]
    mountpoint: String,

    #[structopt(short, long)]
    image: String,
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
    print!("Password: ");
    std::io::stdout().flush()?;
    let password = rpassword::read_password()?;
    fix_newline(&mut username);
    Ok((username, password))
}

trait IntoExecError<T> {
    fn into_exec_err(self) -> Result<T, ExecError>;
}

impl<T> IntoExecError<T> for anyhow::Result<T> {
    fn into_exec_err(self) -> Result<T, ExecError> {
        self.map_err(|err| ExecError::Other(err.into()))
    }
}

fn create_shell(data: &mut SystemSession) -> Shell<&mut SystemSession> {
    let mut shell = Shell::new(data);
    shell.new_command_noargs("exit", "Stop the filesystem server", |_, _| {
        Err(ExecError::Quit)
    });

    shell.new_command(
        "useradd",
        "Add new user to the system",
        1,
        |_, sys, args| {
            let username = args[0];
            sys.useradd(username.into()).into_exec_err()
        },
    );

    shell.new_command(
        "permadd",
        "Add permissions to the file",
        3,
        |_, sys, args| {
            let user = args[0];
            let perm = args[1];
            let path = args[2];
            sys.add_perm(user, perm, path).into_exec_err()
        },
    );

    shell
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
            img.unpack()
        }
        Err(err) if err.kind() == ErrorKind::NotFound => System::new(),
        Err(err) => return Err(err.into()),
    };

    let (username, password) = read_credentials()?;

    let (mut sys, fs) = system.login(&username, &password)?;

    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let handler = fs.run(&opt.mountpoint)?;

    {
        let mut shell = create_shell(&mut sys);
        shell.run_loop(&mut ShellIO::default());
    }

    handler.join();

    let image = sys
        .logout()
        .pack()
        // TODO: proper error handling
        .map_err(|_| anyhow::anyhow!("there should be no more handlers"))?;

    let file = std::fs::File::create(opt.image)?;
    bincode::serialize_into(file, &image)?;

    Ok(())
}
