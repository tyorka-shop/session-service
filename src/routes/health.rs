use actix_web::HttpResponse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct Health {
    status: String,
}

#[get("/health")]
pub async fn health() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/json")
        .json(Health {
            status: "Ok".to_string(),
        })
}
