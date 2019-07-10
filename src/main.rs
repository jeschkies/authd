mod error;

use crate::error::Error;

use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use env_logger;
use jsonwebtoken::{dangerous_unsafe_decode, encode, Algorithm, Header};
use log::info;
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

/// The decoded claim from the authentication token.
///
/// * `exp` - The expiration time of the authentication token.
#[derive(Debug, Deserialize)]
struct AuthenticationClaim {
    #[serde(with = "ts_seconds")]
    exp: DateTime<Utc>,
}

struct State {
    token: AuthenticationToken,
    claim: AuthenticationClaim,
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

    let mut client = Client::builder();
    if let Some(ref p) = opts.cert {
        let cert = load_custom_certificate(p)?;
        client = client.add_root_certificate(cert);
    };
    let client = client.build()?;

    // load secret
    let mut secret = Vec::new();
    File::open(opts.private_key)?.read_to_end(&mut secret)?;

    let mut state: Option<State> = Option::None;

    loop {
        // Post-mortem: Nullify authentication token if token file was removed
        // match file_events.try_recv() {
        //   Ok(Event {event: EventKind(Remove(..), ...}) -> state = None;
        //   Err(TryRecvError::Empty) -> ignore
        // }

        // Refresh authentication token if not set.
        if state.is_none() {
            let login_request = login_request(&client, &uri, &secret)?;

            let auth_token: AuthenticationToken = client.execute(login_request)?.json()?;

            // write token to file
            info!("Saving {:?} to {:?}", auth_token, opts.token);
            File::create(&opts.token)?.write_all(auth_token.token.as_bytes())?;

            let auth_claim =
                dangerous_unsafe_decode::<AuthenticationClaim>(auth_token.token.as_str())?;
            info!("claim = {:?}", auth_claim.claims.exp);

            state = Some(State {
                token: auth_token,
                claim: auth_claim.claims,
            });
        }

        // Pre-mortem: Nullify authentication token and trigger refresh if it expired.
        if let Some(State {
            claim: AuthenticationClaim { exp },
            ..
        }) = state
        {
            if exp < Utc::now() {
                info!("Authentication token expired.");
                state = None;
            }
        }
    }

    Ok(())
}
