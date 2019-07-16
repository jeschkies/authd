//! authd(2)
//!
//! 1. Launch a DC/OS strict cluster.
//! 2. Create key pair:
//! ```
//! dcos security org service-accounts keypair usi.private.pem usi.pub.pem
//! ```
//! 3. Create user strict-usi:
//! ```
//! dcos security org service-accounts create -p usi.pub.pem -d "For testing USI on strict" strict-usi}
//! ```
//! 4. Download SSL certs:
//! ```
//! wget --no-check-certificate -O dcos-ca.crt "$(dcos config show core.dcos_url)/ca/dcos-ca.crt"
//! ```
//! 5. Convert the private key
//! ```
//! openssl rsa -in usi.private.pem -outform DER -out usi.private.der
//! ```
//! 6. Run with `cargo run`
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
