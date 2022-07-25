use crate::cert::download_certs;
use crate::config::Config;
use actix_web::web::{Data, Form, Query};
use actix_web::HttpResponse;
use cookie::{CookieBuilder, Expiration};
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use time::ext::NumericalDuration;
use std::error::Error;
use std::fmt;
use time::OffsetDateTime;
use url::{Position, Url};

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
    ExpiredToken,
    InvalidToken,
}

impl Error for LoginError {}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LoginError::KidNotFound => write!(f, "kid not found"),
            LoginError::DownloadCerts => write!(f, "Can not download certs"),
            LoginError::NotGranted => write!(f, "Not granted"),
            LoginError::ExpiredToken => write!(f, "Expired token"),
            LoginError::InvalidToken => write!(f, "Invalid token"),
        }
    }
}

#[post("/login")]
pub async fn login(
    req: Form<LoginRequest>,
    query: Query<QueryParameters>,
    cfg: Data<Config>,
) -> HttpResponse {
    if !is_allowd_origin(&query.returnTo, &cfg.allowed_origins) {
        error!("Origin not allowed: {}", query.returnTo);
        return HttpResponse::Unauthorized().body("Origin not allowed");
    }

    let email = match auth(&req.credential, &cfg.granted_emails).await {
        Ok(email) => email,
        Err(e) => {
            error!("{}", e);
            return HttpResponse::Unauthorized().body(format!("{err}", err = e));
        }
    };

    let token = match create_token(&email, &cfg.secret.as_bytes(), cfg.token_lifetime) {
        Ok(token) => token,
        Err(e) => {
            error!("{}", e);
            return HttpResponse::InternalServerError()
                .body(format!("Can not create new token: {}", e));
        }
    };

    let expiration =
        Expiration::DateTime(OffsetDateTime::now_utc().checked_add(cfg.token_lifetime.seconds()).unwrap());

    let cookies = CookieBuilder::new("access_token", token)
        .expires(expiration)
        .domain(&cfg.domain)
        .finish();

    return HttpResponse::MovedPermanently()
        .cookie(cookies)
        .insert_header(("Location", query.returnTo.clone()))
        .body("");
}

async fn auth(token: &str, granted_emails: &Vec<String>) -> Result<String, LoginError> {
    let key = match get_decoding_key(&token).await {
        Ok(key) => key,
        Err(e) => {
            error!("{}", e);
            return Err(e);
        }
    };

    match decode::<Claims>(&token, &key, &Validation::new(Algorithm::RS256)) {
        Ok(decoded) => {
            if !granted_emails.contains(&decoded.claims.email) {
                error!("Not grunted {}", decoded.claims.email);
                return Err(LoginError::NotGranted);
            }

            return Ok(decoded.claims.email);
        }
        Err(e) => {
            error!("{}", e);
            match e.kind() {
                ErrorKind::ExpiredSignature => return Err(LoginError::ExpiredToken),
                _ => return Err(LoginError::InvalidToken),
            }
        }
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
    let expiration =
        OffsetDateTime::now_utc().checked_add(token_lifetime.seconds()).unwrap().unix_timestamp();

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

fn is_allowd_origin(origin: &str, allowed_origins: &Vec<String>) -> bool {
    let host = match Url::parse(origin) {
        Ok(url) => url[Position::BeforeScheme..Position::BeforePath].to_string(),
        Err(_) => return false,
    };
    allowed_origins.contains(&host)
}
