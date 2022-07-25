use serde::{Deserialize, Serialize};
use rand::{distributions::Alphanumeric, Rng}; // 0.8

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
  pub port: String,
  pub secret: String,
  pub granted_emails: Vec<String>,
  pub token_lifetime: i64,
}

impl ::std::default::Default for Config {
  fn default() -> Self {
    Self {
      port: "3002".into(),
      secret: rand::thread_rng().sample_iter(&Alphanumeric).take(256).map(char::from).collect(),
      granted_emails: vec![],
      token_lifetime: 3600,
    }
  }
}

pub fn load() -> Config {
  confy::load::<Config>("tyorka-session-service").unwrap()
}