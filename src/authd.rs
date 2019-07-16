//! Main authentication daemon loop.
//!

use crate::client::{AuthenticationClaim, AuthenticationToken, Client};
use crate::error::Error;

use chrono::Utc;
use crossbeam_channel::{after, never, select, unbounded, Receiver};
use log::{debug, info, warn};
use notify::event::EventKind;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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

        // Watch token file for removal.
        // We have to keep the watcher around.
        let (token_file_event, _watcher) = self.subscribe_to_token_file()?;

        // Refresh authentication token when token file was removed or token expired.
        loop {
            select! {
                recv(token_file_event) -> event => self.handle_token_file_event(event?)?,
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

    /// Pre-mortem: Set a token expiration to trigger a refresh.
    fn set_token_expiration_timer(&mut self) -> Result<(), Error> {
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

    /// Post-morten: The token file was removed.
    fn handle_token_file_event(
        &mut self,
        event: Result<Event, notify::Error>,
    ) -> Result<(), Error> {
        if self.is_remove(event?) {
            self.refresh_token()?
        }
        Ok(())
    }

    /// Check whether the token file was removed or some other event happened.
    fn is_remove(&self, event: Event) -> bool {
        match event.kind {
            EventKind::Remove(_) => {
                info!("Token file {:?} was removed", self.token_path);
                true
            }
            other => {
                debug!(
                    "Other event on token file {:?}: {:?}",
                    self.token_path, other
                );
                false
            }
        }
    }

    /// Watch the token file for removal.
    ///
    /// The `watcher` is moved out to keep its thread alive.
    fn subscribe_to_token_file(
        &self,
    ) -> Result<(Receiver<notify::Result<Event>>, RecommendedWatcher), Error> {
        let (tx, rx) = unbounded();

        let mut watcher: RecommendedWatcher = Watcher::new(tx, Duration::from_secs(2))?;
        watcher.watch(&self.token_path, RecursiveMode::NonRecursive)?;
        Ok((rx, watcher))
    }
}
