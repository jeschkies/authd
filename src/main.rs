
mod error;

use crate::error::Error;

use jsonwebtoken::{encode, Algorithm, Header};
use reqwest::{Certificate, Client, Request};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Serialize)]
struct Claim {
    uid: String,
    exp: u64,
}

fn login_request(
    client: &Client,
    uri: &str,
    secret: &[u8],
) -> Result<Request, Error> {
    let mut data = HashMap::new();

    let uid: String = "strict-usi".to_owned(); // TODO: pass user.
    let claim = Claim {
        uid: uid.clone(),
        exp: 0,
    };
    let service_login_token = encode(&Header::new(Algorithm::RS256), &claim, secret)?;

    data.insert("uid", uid.as_str());
    data.insert("token", service_login_token.as_str());
    let request = client.post(uri).json(&data).build()?;
    Ok(request)
}

fn load_custom_certificate<P: AsRef<Path>>(
    path: P,
) -> Result<Certificate, Error> {
    let mut buf = Vec::new();
    File::open(path)?.read_to_end(&mut buf)?;
    let cert = Certificate::from_pem(&buf)?;
    Ok(cert)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let uri = "https://kjeschkie-elasticl-56l539m0xkcm-551146504.us-west-2.elb.amazonaws.com/acs/api/v1/auth/login";

    let cert = load_custom_certificate("dcos-ca.crt")?;

    let client = Client::builder().add_root_certificate(cert).build()?;

    let secret = "my secret".as_ref();
    let login_request = login_request(&client, uri, secret)?;

    let body = client.execute(login_request)?.text()?;

    println!("body = {:?}", body);
    Ok(())
}
