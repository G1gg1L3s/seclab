use std::io::{ErrorKind, Write};

use seclab::{System, SystemImage};
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

    let (username, password) = dbg!(read_credentials()?);

    let session = system.login(&username, &password)?;

    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let handler = session.run(&opt.mountpoint)?;

    let mut line = String::new();
    loop {
        std::io::stdin().read_line(&mut line)?;
        if line.contains("exit") {
            break;
        }
    }

    handler.join();

    let image = system
        .pack()
        // TODO: proper error handling
        .map_err(|_| anyhow::anyhow!("there should be no more handlers"))?;

    let file = std::fs::File::create(opt.image)?;
    bincode::serialize_into(file, &image)?;

    Ok(())
}
