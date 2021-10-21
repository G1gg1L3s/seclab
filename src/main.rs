use fuser::MountOption;
use seclab::Fs;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "tmp")]
    mountpoint: String,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();

    if let Err(err) = std::fs::create_dir(&opt.mountpoint) {
        match err.kind() {
            std::io::ErrorKind::AlreadyExists => {}
            _ => anyhow::bail!("creating the directory: {}", err),
        }
    };

    let fs = Fs::new_test();

    let options = vec![
        MountOption::FSName("seclab".to_string()),
        MountOption::AutoUnmount,
    ];

    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    fuser::mount2(fs, &opt.mountpoint, &options).map_err(Into::into)
}
