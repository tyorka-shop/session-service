use crate::config::Config;
use actix_web::web::{Data, Json};
use actix_web::HttpResponse;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    email: String,
    exp: u64,
}

#[derive(Debug)]
enum VerifyError {
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

fn verify_token(
    token: &str,
    secret: &[u8],
    granted_emails: &Vec<String>,
) -> Result<(), VerifyError> {
    match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(&secret),
        &Validation::new(Algorithm::RS256),
    ) {
        Err(e) => match e.kind() {
            ErrorKind::ExpiredSignature => Err(VerifyError::Expired),
            _ => Err(VerifyError::Parse),
        },
        Ok(decoded) => {
            if !granted_emails.contains(&decoded.claims.email) {
                return Err(VerifyError::NotGrunted);
            }

            return Ok(());
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyRequest {
    token: String,
}

#[post("/verify")]
pub async fn verify(req: Json<VerifyRequest>, cfg: Data<Config>) -> HttpResponse {
    match verify_token(&req.token, &cfg.secret.as_bytes(), &cfg.granted_emails) {
        Err(e) => HttpResponse::Unauthorized()
            .body(format!("{err}", err = e))
            .await
            .unwrap(),
        Ok(_) => HttpResponse::Ok().body(""),
    }
}
