//! Main authentication daemon loop.
//!

use crate::client::{AuthenticationClaim, AuthenticationToken, Client};
use crate::error::Error;

use chrono::Utc;
use crossbeam_channel::{after, never, select, Receiver};
use log::{info, warn};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::time::Instant;

pub struct Authd {
    client: Client,
    auth_token: Option<AuthenticationToken>,
    token_path: PathBuf,
    token_expired: Receiver<Instant>,
}

impl Authd {
    pub fn new(
        endpoint: String,
        secret: Vec<u8>,
        token_path: PathBuf,
        cert: Option<PathBuf>,
    ) -> Result<Authd, Error> {
        let client = Client::new(endpoint, secret, cert)?;
        Ok(Authd {
            client,
            auth_token: None,
            token_path,
            token_expired: never(),
        })
    }

    /// Start the daemon loop.
    pub fn run(mut self) -> Result<(), Error> {
        // Refresh authentication token at the start.
        self.refresh_token()?;

        // Refresh authentication token when token file was removed or token expired.
        loop {
            select! {
            //  recv(self.token_file_event) -> event => if is_remove(event) self.refesh_token()?,
                recv(self.token_expired) -> _instant => self.refresh_token()?,
            }
        }
    }

    fn refresh_token(&mut self) -> Result<(), Error> {
        info!("Refreshing authentication token.");
        let auth_token: AuthenticationToken = self.client.login()?;

        // write token to file
        info!("Saving {:?} to {:?}", auth_token, self.token_path);
        File::create(&self.token_path)?.write_all(auth_token.token.as_bytes())?;

        self.auth_token = Some(auth_token);
        self.set_token_expiration_timer()?;
        Ok(())
    }

    fn set_token_expiration_timer(&mut self) -> Result<(), Error> {
        // Pre-mortem: Nullify authentication token and trigger refresh if it expired.
        if let Some(ref token) = self.auth_token {
            let AuthenticationClaim { exp } = token.claim()?;
            match (exp - Utc::now()).to_std() {
                Ok(duration) => {
                    info!("Set token expiration to {:?}", exp);
                    self.token_expired = after(duration);
                }
                Err(error) => {
                    warn!("Could not set token expiration: {:?}", error);
                    self.token_expired = never();
                }
            }
        }
        Ok(())
    }
}
