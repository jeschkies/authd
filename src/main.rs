mod error;

use crate::error::Error;

use env_logger;
use log::info;
use jsonwebtoken::{encode, Algorithm, Header};
use reqwest::{Certificate, Client, Request};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use structopt::StructOpt;

/// A JWT Claim.
///
/// * `uid` - The service user id.
/// * `exp` - Unix timestamp when login request token expires.
#[derive(Debug, Serialize)]
struct Claim {
    uid: String,
    exp: u64,
}

/// An Authentication Token retrieved.
///
/// * `token` - The actual authentication token.
#[derive(Debug, Deserialize)]
struct AuthenticationToken {
    token: String,
}

/// The request body to login.
///
/// * `uid`   - The service user id.
/// * `token` - The service login json web token.
#[derive(Debug, Serialize)]
struct LoginRequestBody {
    uid: String,
    token: String,
}

/// Constructs a login request.
///
/// * `client` - The HTTP client used.
/// * `uri`    - The request URL pointing to the DC/OS login.
/// * `secret` - The service account private key.
fn login_request(client: &Client, uri: &str, secret: &[u8]) -> Result<Request, Error> {
    let uid: String = String::from("strict-usi"); // TODO: pass user.
    let claim = Claim {
        uid: uid.clone(),
        exp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1000,
    };
    let service_login_token = encode(&Header::new(Algorithm::RS256), &claim, secret)?;

    let data = LoginRequestBody {
        uid: uid,
        token: service_login_token,
    };
    let request = client.post(uri).json(&data).build()?;
    Ok(request)
}

/// Loads a custom certificate for HTTPs calls to DC/OS.
///
/// * `path` - The path of the certification file.
fn load_custom_certificate<P: AsRef<Path>>(path: P) -> Result<Certificate, Error> {
    let mut buf = Vec::new();
    File::open(path)?.read_to_end(&mut buf)?;
    let cert = Certificate::from_pem(&buf)?;
    Ok(cert)
}


#[derive(Debug, StructOpt)]
#[structopt(name = "authd", about = "An authentication daemon.")]
struct Opt {

    #[structopt(long, default_value = ".ssl/ca-bundle.crt", parse(from_os_str))]
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
    let cert = load_custom_certificate(opts.cert)?;

    let mut client = Client::builder();

    if let Some(ref p) = opts.cert {
        let cert = load_custom_certificate(p)?;
        client = client.add_root_certificate(cert);
    };

    let client = client.build()?;

    // load secret
    let mut secret = Vec::new();
    File::open(opts.private_key)?.read_to_end(&mut secret)?;
    let login_request = login_request(&client, &uri, &secret)?;

    let body: AuthenticationToken = client.execute(login_request)?.json()?;

    // write token to file
    File::create(opts.token)?.write_all(body.token.as_bytes())?;

    info!("body = {:?}", body);
    Ok(())
}
