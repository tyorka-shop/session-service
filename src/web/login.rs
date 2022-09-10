use config::Config;
use cookie::{CookieBuilder, Expiration};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::result::Result;
use time::ext::NumericalDuration;
use time::OffsetDateTime;
use url::{Position, Url};
use warp::http::response::Builder;
use warp::http::Error;

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

pub async fn login(
    query: QueryParameters,
    req: LoginRequest,
    cfg: Config,
) -> Result<impl warp::Reply, Error> {
    if !is_allowd_origin(&query.returnTo, &cfg.allowed_origins) {
        error!("Origin not allowed: {}", query.returnTo);
        return Builder::new()
            .status(StatusCode::UNAUTHORIZED)
            .body("Origin not allowed".into());
    }

    let email = match crate::google_auth::auth(&req.credential, &cfg.granted_emails).await {
        Ok(email) => email,
        Err(e) => {
            error!("{}", e);
            return Builder::new()
                .status(StatusCode::UNAUTHORIZED)
                .body("Unauthorized");
        }
    };

    let token = match crate::token::create(&email, &cfg.secret.as_bytes(), cfg.token_lifetime) {
        Ok(token) => token,
        Err(e) => {
            error!("{}", e);
            return Builder::new()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("");
        }
    };

    let expiration = Expiration::DateTime(
        OffsetDateTime::now_utc()
            .checked_add(cfg.token_lifetime.seconds())
            .unwrap(),
    );

    let cookies = CookieBuilder::new("access_token", token)
        .expires(expiration)
        .domain(&cfg.domain)
        .finish();

    Builder::new()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header("Set-Cookie", cookies.to_string())
        .header("Location", query.returnTo.clone())
        .body("".into())
}

fn is_allowd_origin(origin: &str, allowed_origins: &Vec<String>) -> bool {
    let host = match Url::parse(origin) {
        Ok(url) => url[Position::BeforeScheme..Position::BeforePath].to_string(),
        Err(_) => {
            error!("Can not parse origin: {}", origin);
            return false;
        }
    };
    allowed_origins.contains(&host)
}
