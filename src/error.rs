use jsonwebtoken;
use reqwest;
use std::{convert, error, fmt, io};

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
            Error::Jwt(e) => Some(e) ,
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

impl convert::From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e)
    }
}

impl convert::From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl convert::From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Error::Jwt(e)
    }
}
