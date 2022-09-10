use crate::cert::download_certs;
use crate::token::Claims;
use jsonwebtoken::{decode, decode_header, errors::ErrorKind, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::result::Result;

use log::error;

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginRequest {
    credential: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct QueryParameters {
    pub returnTo: String,
}

#[derive(Debug)]
pub enum GoogleAuthError {
    KidNotFound,
    DownloadCerts,
    NotGranted,
    ExpiredToken,
    InvalidToken,
}

impl std::error::Error for GoogleAuthError {}

impl fmt::Display for GoogleAuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GoogleAuthError::KidNotFound => write!(f, "kid not found"),
            GoogleAuthError::DownloadCerts => write!(f, "Can not download certs"),
            GoogleAuthError::NotGranted => write!(f, "Not granted"),
            GoogleAuthError::ExpiredToken => write!(f, "Expired token"),
            GoogleAuthError::InvalidToken => write!(f, "Invalid token"),
        }
    }
}

pub async fn auth(token: &str, granted_emails: &Vec<String>) -> Result<String, GoogleAuthError> {
    let key = get_decoding_key(&token).await?;

    match decode::<Claims>(&token, &key, &Validation::new(Algorithm::RS256)) {
        Ok(decoded) => {
            if !granted_emails.contains(&decoded.claims.email) {
                error!("Not grunted {}", decoded.claims.email);
                return Err(GoogleAuthError::NotGranted);
            }

            Ok(decoded.claims.email)
        }
        Err(e) => match e.kind() {
            ErrorKind::ExpiredSignature => Err(GoogleAuthError::ExpiredToken),
            _ => Err(GoogleAuthError::InvalidToken),
        },
    }
}

async fn get_decoding_key<'a>(token: &'a str) -> Result<DecodingKey<'a>, GoogleAuthError> {
    let payload = decode_header(token).map_err(|_| GoogleAuthError::InvalidToken)?;

    let kid = payload.kid.ok_or(GoogleAuthError::KidNotFound)?;

    let cert = download_certs(&kid)
        .await
        .map_err(|_| GoogleAuthError::DownloadCerts)?;

    Ok(DecodingKey::from_rsa_components(&cert.n, &cert.e).into_static())
}
