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

use jsonwebtoken;
use reqwest;
use std::{convert::From, error, fmt, io};

#[derive(Debug)]
pub enum Error {
    Http(reqwest::Error),
    Io(io::Error),
    Jwt(jsonwebtoken::errors::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Authd Error"
    }

    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Http(e) => Some(e),
            Error::Io(e) => Some(e),
            Error::Jwt(e) => Some(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Http(ref s) => write!(f, "Http error: {}", s),
            Error::Io(ref s) => write!(f, "IO error: {}", s),
            Error::Jwt(ref s) => write!(f, "JWT generation error: {}", s),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Error::Jwt(e)
    }
}
