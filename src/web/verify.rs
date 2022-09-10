use serde::{Deserialize, Serialize};
use std::result::Result;
use warp::http::Error;

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyRequest {
    token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VerifyResponse {
    email: String,
}

pub async fn verify(req: VerifyRequest, cfg: config::Config) -> Result<impl warp::Reply, Error> {
    let email = crate::token::verify(&req.token, cfg.secret.as_bytes(), &cfg.granted_emails).unwrap();

    Ok(warp::reply::json(&VerifyResponse { email }))
}
