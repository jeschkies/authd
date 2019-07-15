use crossbeam_channel;
use jsonwebtoken;
use notify;
use reqwest;
use std::{convert::From, error, fmt, io};

#[derive(Debug)]
pub enum Error {
    Crossbeam(crossbeam_channel::RecvError),
    Http(reqwest::Error),
    Io(io::Error),
    Jwt(jsonwebtoken::errors::Error),
    Notify(notify::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Authd Error"
    }

    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Crossbeam(e) => Some(e),
            Error::Http(e) => Some(e),
            Error::Io(e) => Some(e),
            Error::Jwt(e) => Some(e),
            Error::Notify(e) => Some(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Crossbeam(ref s) => write!(f, "Internal message channel error: {}", s),
            Error::Http(ref s) => write!(f, "Http error: {}", s),
            Error::Io(ref s) => write!(f, "IO error: {}", s),
            Error::Jwt(ref s) => write!(f, "JWT generation error: {}", s),
            Error::Notify(ref s) => write!(f, "Token file notification error: {}", s),
        }
    }
}

impl From<crossbeam_channel::RecvError> for Error {
    fn from(e: crossbeam_channel::RecvError) -> Self {
        Error::Crossbeam(e)
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

impl From<notify::Error> for Error {
    fn from(e: notify::Error) -> Self {
        Error::Notify(e)
    }
}
