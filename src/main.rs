mod authd;
mod client;
mod error;

use crate::authd::Authd;

use env_logger;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "authd", about = "An authentication daemon.")]
struct Opt {
    #[structopt(long, parse(from_os_str))]
    /// Path to a custom certificate for securing HTTP connections.
    cert: Option<PathBuf>,

    #[structopt(long, default_value = "https://master.mesos")]
    /// Authentication endpoint to use.
    endpoint: String,

    #[structopt(parse(from_os_str))]
    /// Path to private RSA key in DER format.
    private_key: PathBuf,

    #[structopt(parse(from_os_str))]
    /// Target path for authentication token.
    token: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let opts = Opt::from_args();
    let uri = format!("{}/acs/api/v1/auth/login", opts.endpoint);

    // load secret
    let mut secret = Vec::new();
    File::open(opts.private_key)?.read_to_end(&mut secret)?;

    let authd = Authd::new(uri, secret, opts.token, opts.cert)?;
    Ok(authd.run()?)
}
