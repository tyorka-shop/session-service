use crate::cert::download_certs;
use crate::config::Config;
use actix_web::http::CookieBuilder;
use actix_web::web::{Data, Json};
use actix_web::HttpResponse;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use time::OffsetDateTime;

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginRequest {
    credential: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    email: String,
    exp: i64,
}

#[derive(Debug)]
enum LoginError {
    KidNotFound,
    DownloadCerts,
    NotGranted,
    InvalidToken,
}

impl Error for LoginError {}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LoginError::KidNotFound => write!(f, "kid not found"),
            LoginError::DownloadCerts => write!(f, "Can not download certs"),
            LoginError::NotGranted => write!(f, "Not granted"),
            LoginError::InvalidToken => write!(f, "Invalid token"),
        }
    }
}

#[post("/login")]
pub async fn login(req: Json<LoginRequest>, cfg: Data<Config>) -> HttpResponse {
    let email = match auth(&req.credential, &cfg.granted_emails).await {
        Ok(email) => email,
        Err(e) => {
            return HttpResponse::Unauthorized()
                .body(format!("{err}", err = e))
                .await
                .unwrap();
        }
    };

    let token = match create_token(&email, &cfg.secret.as_bytes(), cfg.token_lifetime) {
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Can not create new token: {}", e))
                .await
                .unwrap();
        }
        Ok(token) => token,
    };

    let expires = OffsetDateTime::from_unix_timestamp(cfg.token_lifetime);
    let cookies = CookieBuilder::new("access_token", token)
        .expires(expires)
        .path("/")
        .finish();

    return HttpResponse::Ok().cookie(cookies).body("").await.unwrap();
}

async fn auth(token: &str, granted_emails: &Vec<String>) -> Result<String, LoginError> {
    let key = match get_decoding_key(&token).await {
        Ok(key) => key,
        Err(e) => {
            return Err(e);
        }
    };

    match decode::<Claims>(&token, &key, &Validation::new(Algorithm::RS256)) {
        Ok(decoded) => {
            if !granted_emails.contains(&decoded.claims.email) {
                return Err(LoginError::NotGranted);
            }

            return Ok(decoded.claims.email);
        }
        Err(_) => Err(LoginError::InvalidToken),
    }
}

async fn get_decoding_key<'a>(token: &'a str) -> Result<DecodingKey<'a>, LoginError> {
    let kid = match get_kid(token) {
        Ok(kid) => kid,
        Err(_) => {
            return Err(LoginError::KidNotFound);
        }
    };

    let cert = download_certs(&kid).await;

    let cert = match cert {
        Ok(cert) => cert,
        Err(_) => {
            return Err(LoginError::DownloadCerts);
        }
    };

    let key = DecodingKey::from_rsa_components(&cert.n, &cert.e).into_static();

    return Ok(key);
}

fn create_token(email: &str, secret: &[u8], token_lifetime: i64) -> Result<String, Box<dyn Error>> {
    let exp = OffsetDateTime::from_unix_timestamp(token_lifetime).unix_timestamp();

    let claims = Claims {
        email: email.to_string(),
        exp: exp,
    };

    match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    ) {
        Ok(token) => Ok(token),
        Err(e) => return Err(e.into()),
    }
}
#[derive(Debug, Deserialize, Serialize)]
struct JWTHeader {
    typ: String,
    alg: String,
    kid: String,
}

fn get_kid(token: &str) -> Result<String, Box<dyn Error>> {
    let parts = token.split(".").collect::<Vec<&str>>();
    if parts.len() != 3 {
        return Err("Invalid token".into());
    }
    let header = parts[0];
    let header = base64::decode(&header)?;
    let header = String::from_utf8(header)?;
    let header = serde_json::from_str::<JWTHeader>(&header)?;
    Ok(header.kid)
}
