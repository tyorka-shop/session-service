use reqwest::get;
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

pub async fn download_certs(kid: &str) -> Result<Cert, CertificateError> {
    let certs = get("https://www.googleapis.com/oauth2/v3/certs")
        .await?
        .json::<Certs>()
        .await?;

    let cert = match certs.keys.into_iter().find(|cert| cert.kid == kid) {
        Some(cert) => cert,
        None => return Err(CertificateError::NotFound),
    };

    //TODO: cache cert
    Ok(cert)
}
