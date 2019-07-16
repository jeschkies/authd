//! The actual authentication client.
//!

use crate::error::Error;

use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use jsonwebtoken::{dangerous_unsafe_decode, encode, Algorithm, Header};
use reqwest;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// An Authentication Token retrieved.
///
/// * `token` - The actual authentication token.
#[derive(Debug, Deserialize)]
pub struct AuthenticationToken {
    pub token: String,
}

/// The decoded claim from the authentication token.
///
/// * `exp` - The expiration time of the authentication token.
#[derive(Debug, Deserialize)]
pub struct AuthenticationClaim {
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
}

impl AuthenticationToken {
    pub fn claim(&self) -> Result<AuthenticationClaim, Error> {
        let auth_claim = dangerous_unsafe_decode::<AuthenticationClaim>(self.token.as_str())?;
        Ok(auth_claim.claims)
    }
}

pub struct Client {
    http_client: reqwest::Client,
    secret: Vec<u8>,
    endpoint: String,
}

impl Client {
    pub fn new(endpoint: String, secret: Vec<u8>, cert: Option<PathBuf>) -> Result<Client, Error> {
        let http_client = Client::create_client(cert)?;
        Ok(Client {
            http_client,
            secret,
            endpoint,
        })
    }

    fn create_client(cert: Option<PathBuf>) -> Result<reqwest::Client, Error> {
        let mut builder = reqwest::Client::builder();
        if let Some(ref p) = cert {
            let cert = Client::load_custom_certificate(p)?;
            builder = builder.add_root_certificate(cert);
        };
        let client = builder.build()?;
        Ok(client)
    }

    /// Loads a custom certificate for HTTPs calls to DC/OS.
    ///
    /// # Arguments
    ///
    /// * `path` - The path of the certification file.
    fn load_custom_certificate<P: AsRef<Path>>(path: P) -> Result<reqwest::Certificate, Error> {
        let mut buf = Vec::new();
        File::open(path)?.read_to_end(&mut buf)?;
        let cert = reqwest::Certificate::from_pem(&buf)?;
        Ok(cert)
    }

    pub fn login(&self) -> Result<AuthenticationToken, Error> {
        let login_request = self.login_request()?;
        Ok(self.http_client.execute(login_request)?.json()?)
    }

    /// Constructs a login request.
    ///
    /// # Arguments
    ///
    /// * `client` - The HTTP client used.
    /// * `uri`    - The request URL pointing to the DC/OS login.
    /// * `secret` - The service account private key.
    fn login_request(&self) -> Result<reqwest::Request, Error> {
        let uid: String = String::from("strict-usi"); // TODO: pass user.
        let claim = Claim {
            uid: uid.clone(),
            exp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 1000,
        };
        let service_login_token = encode(&Header::new(Algorithm::RS256), &claim, &self.secret)?;

        let data = LoginRequestBody {
            uid: uid,
            token: service_login_token,
        };
        let request = self
            .http_client
            .post(self.endpoint.as_str())
            .json(&data)
            .build()?;
        Ok(request)
    }
}

/// The request body to login.
///
/// # Arguments
///
/// * `uid`   - The service user id.
/// * `token` - The service login json web token.
#[derive(Debug, Serialize)]
struct LoginRequestBody {
    uid: String,
    token: String,
}

// TODO: this is verify similar to AuthenticationClaim. Maybe they should be the same.

/// A JWT Claim.
///
/// # Arguments
///
/// * `uid` - The service user id.
/// * `exp` - Unix timestamp when login request token expires.
#[derive(Debug, Serialize)]
struct Claim {
    uid: String,
    exp: u64,
}
