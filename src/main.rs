mod cache;
mod cert;
mod google_auth;
mod token;
mod grpc;
mod web;

#[tokio::main]
async fn main() {
    env_logger::init();
    let cfg = config::load("tyorka-session-service");

    let web = web::make_server(cfg.clone());
    let grpc = grpc::make_server(cfg.clone());

    let (_, _) = tokio::join!(web, grpc);
}
