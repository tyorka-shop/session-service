use lazy_static::lazy_static;
use regex::Regex;
use reqwest::Response;
use reqwest::get;
use reqwest::header::CACHE_CONTROL;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::str;
use std::sync::Mutex;
use time::ext::NumericalDuration;
use time::OffsetDateTime;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Cert {
    pub e: String,
    pub n: String,
    pub kid: String,
}

pub struct CacheEntry {
    cert: Cert,
    expiring: i64,
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

lazy_static! {
    static ref CACHE: Mutex<HashMap<String, CacheEntry>> = Mutex::new(HashMap::new());
}

fn get_from_cache(key: &str) -> Option<Cert> {
    let cache = CACHE.lock().unwrap();
    match cache.get(key.into()) {
        Some(entry) => {
            if entry.expiring > OffsetDateTime::now_utc().unix_timestamp() {
                return Some(entry.cert.clone());
            }
            return None;
        }
        None => return None,
    };
}

fn insert_into_cache(key: &str, cert: &Cert, ttl: i64) {
    let mut cache = CACHE.lock().unwrap();

    let expiring = OffsetDateTime::now_utc()
        .checked_add(ttl.seconds())
        .unwrap()
        .unix_timestamp();

    cache.insert(
        String::from(key),
        CacheEntry {
            expiring,
            cert: cert.clone(),
        },
    );
}

fn get_max_age(resp: &Response) -> i64 {
    let cache_control = match resp.headers().get(CACHE_CONTROL) {
        Some(cache_control) => cache_control.to_str().unwrap().to_string(),
        None => "".to_string(),
    };

    let re = Regex::new(r"max-age=(\d+)").unwrap();

    let duration = match re.captures(&cache_control) {
        Some(caps) => {
            if caps.len() >= 2 {
                caps[1].parse::<i64>().unwrap()
            } else {
                3600 as i64
            }
        }
        None => 3600 as i64,
    };

    duration
}

pub async fn download_certs(kid: &str) -> Result<Cert, CertificateError> {
    match get_from_cache(kid.into()) {
        Some(cert) => {
            return Ok(cert);
        }
        None => {}
    }

    dbg!("Downloading certificate");

    let resp = get("https://www.googleapis.com/oauth2/v3/certs").await?;

    let cache_ttl = get_max_age(&resp);

    let certs = resp.json::<Certs>().await?;

    let cert = match certs.keys.into_iter().find(|cert| cert.kid == kid) {
        Some(cert) => cert,
        None => return Err(CertificateError::NotFound),
    };

    insert_into_cache(&kid, &cert, cache_ttl);

    Ok(cert)
}
