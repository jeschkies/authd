//! Main authentication daemon loop.
//!

use crate::client::{AuthenticationClaim, AuthenticationToken, Client};
use crate::error::Error;

use chrono::Utc;
use log::info;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

struct State {
    token: AuthenticationToken,
}

pub struct Authd {
    client: Client,
    state: Option<State>,
    token_path: PathBuf,
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
            state: None,
            token_path,
        })
    }

    /// Start the daemon loop.
    pub fn run(mut self) -> Result<(), Error> {
        loop {
            // Post-mortem: Nullify authentication token if token file was removed
            // match file_events.try_recv() {
            //   Ok(Event {event: EventKind(Remove(..), ...}) -> state = None;
            //   Err(TryRecvError::Empty) -> ignore
            // }

            // Refresh authentication token if not set.
            if self.state.is_none() {
                let auth_token: AuthenticationToken = self.client.login()?;

                // write token to file
                info!("Saving {:?} to {:?}", auth_token, self.token_path);
                File::create(&self.token_path)?.write_all(auth_token.token.as_bytes())?;

                info!("claim = {:?}", auth_token.claim()?.exp);

                self.state = Some(State { token: auth_token });
            }

            // Pre-mortem: Nullify authentication token and trigger refresh if it expired.
            if let Some(State { ref token }) = self.state {
                let AuthenticationClaim { exp } = token.claim()?;
                if exp < Utc::now() {
                    info!("Authentication token expired.");
                    self.state = None;
                }
            }
        }
    }
}
