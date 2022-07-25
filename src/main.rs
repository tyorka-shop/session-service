#[macro_use]
extern crate actix_web;

use std::io;

use actix_web::{middleware, App, HttpServer};

mod config;
mod routes;
mod cert;

#[actix_rt::main]
async fn main() -> io::Result<()> {
  env_logger::init();
  let cfg = config::load();
  let port = cfg.port.clone();

  HttpServer::new(move || {
    App::new()
      .wrap(middleware::Logger::default())
      .data(cfg.clone())
      .service(routes::health::health)
      .service(routes::verify::verify)
      .service(routes::login::login)
  })
  .bind(format!("0.0.0.0:{port}", port = port))?
  .run()
  .await
}
