use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation, encode, EncodingKey, Header, errors::ErrorKind};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::result::Result;
use time::ext::NumericalDuration;
use time::OffsetDateTime;

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub email: String,
    pub exp: i64,
}

pub fn create(
    email: &str,
    secret: &[u8],
    token_lifetime: i64,
) -> Result<String, Box<dyn std::error::Error>> {
    let expiration = OffsetDateTime::now_utc()
        .checked_add(token_lifetime.seconds())
        .unwrap()
        .unix_timestamp();

    let claims = Claims {
        email: email.to_string(),
        exp: expiration,
    };

    match encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    ) {
        Ok(token) => Ok(token),
        Err(e) => return Err(e.into()),
    }
}

#[derive(Debug)]
pub enum VerifyError {
    Parse,
    Expired,
    NotGrunted,
}

impl Error for VerifyError {}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VerifyError::Parse => write!(f, "Can not parse certificates"),
            VerifyError::Expired => write!(f, "Token expired"),
            VerifyError::NotGrunted => write!(f, "Not grunted"),
        }
    }
}

pub fn verify(
    token: &str,
    secret: &[u8],
    granted_emails: &Vec<String>,
) -> Result<String, VerifyError> {
    match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(&secret),
        &Validation::new(Algorithm::HS256),
    ) {
        Err(e) => match e.kind() {
            ErrorKind::ExpiredSignature => Err(VerifyError::Expired),
            _ => Err(VerifyError::Parse),
        },
        Ok(decoded) => {
            if !granted_emails.contains(&decoded.claims.email) {
                return Err(VerifyError::NotGrunted);
            }

            return Ok(decoded.claims.email);
        }
    }
}
