use regex::Regex;
use reqwest::{get, header::CACHE_CONTROL, Response};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::str;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Cert {
    pub e: String,
    pub n: String,
    pub kid: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Certs {
    pub keys: Vec<Cert>,
}

#[derive(Debug)]
pub enum CertificateError {
    Http,
    Parse,
    NotFound,
}

impl Error for CertificateError {}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CertificateError::Http => write!(f, "Can not download actual certificates"),
            CertificateError::Parse => write!(f, "Can not parse certificates"),
            CertificateError::NotFound => write!(f, "Certificate with kid not found"),
        }
    }
}

impl From<reqwest::Error> for CertificateError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_decode() {
            return CertificateError::Parse;
        }
        CertificateError::Http
    }
}

fn get_max_age(resp: &Response) -> Option<i64> {
    let cache_control = match resp.headers().get(CACHE_CONTROL) {
        Some(cache_control) => cache_control.to_str().unwrap().to_string(),
        None => return None,
    };

    Regex::new(r"max-age=(\d+)")
        .unwrap()
        .captures(&cache_control)
        .map(|caps| caps.get(1).unwrap().as_str().parse::<i64>().unwrap())
}

pub async fn download_certs(kid: &str) -> Result<Cert, CertificateError> {
    match crate::cache::get(kid) {
        Some(cert) => {
            Ok(cert)
        }
        None => {
            dbg!("Downloading certificates");

            let resp = get("https://www.googleapis.com/oauth2/v3/certs").await?;

            let cache_ttl = get_max_age(&resp).unwrap_or(3600_i64);

            let cert = resp
                .json::<Certs>()
                .await?
                .keys
                .into_iter()
                .find(|cert| cert.kid == kid)
                .ok_or(CertificateError::NotFound)?;

            crate::cache::insert(&kid, &cert, cache_ttl);

            Ok(cert)
        }
    }
}
