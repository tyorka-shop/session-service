use crate::google_auth::GoogleAuth;
use log::info;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use warp::{serve, Filter, Future};

mod login;
mod verify;

use login::{login, LoginRequest, QueryParameters};
use verify::{verify, VerifyRequest};

fn login_route(
    cfg: config::Config,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("login")
        .and(warp::post())
        .and(warp::query::<QueryParameters>())
        .and(warp::body::content_length_limit(1024 * 8))
        .and(warp::body::form::<LoginRequest>())
        .and(warp::any().map(move || cfg.to_owned()))
        .and(warp::any().map(move || GoogleAuth::new()))
        .then(login)
}

fn verify_route(
    cfg: config::Config,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("verify")
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 8))
        .and(warp::body::json::<VerifyRequest>())
        .and(warp::any().map(move || cfg.to_owned()))
        .then(verify)
}

pub fn make_server(cfg: config::Config) -> impl Future<Output = ()> {
    let port = cfg.port.clone();

    let routes = verify_route(cfg.clone()).or(login_route(cfg));

    let addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port.parse::<u16>().unwrap(),
    );

    info!("Web listening on {}", &port);
    serve(routes).run(addr)
}

#[cfg(test)]
mod test_login {
    use reqwest::StatusCode;

    #[tokio::test]
    async fn origin_not_allowed() {
        let route = super::login_route(config::Config {
            allowed_origins: vec!["http://localhost:3000".to_string()],
            ..Default::default()
        });
        let value = warp::test::request()
            .method("POST")
            .path("/login?returnTo=http%3A%2F%2Flocalhost%3A3001%2Fproducts")
            .body("credential=xxx")
            .reply(&route)
            .await;

        assert_eq!(value.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(value.body(), "Origin not allowed");
    }

    #[tokio::test]
    async fn unauthorized() {
        let route = super::login_route(config::Config {
            allowed_origins: vec!["http://localhost:3000".to_string()],
            ..Default::default()
        });
        let value = warp::test::request()
            .method("POST")
            .path("/login?returnTo=http%3A%2F%2Flocalhost%3A3000%2Fproducts")
            .body("credential=xxx")
            .reply(&route)
            .await;

        assert_eq!(value.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(value.body(), "Unauthorized");
    }
}
