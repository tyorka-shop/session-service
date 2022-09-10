use serde::{Deserialize, Serialize};
use rand::{distributions::Alphanumeric, Rng};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
  pub port: String,
  pub secret: String,
  pub domain: String,
  pub token_lifetime: i64,
  pub granted_emails: Vec<String>,
  pub allowed_origins: Vec<String>,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      port: "3002".into(),
      secret: rand::thread_rng().sample_iter(&Alphanumeric).take(256).map(char::from).collect(),
      granted_emails: vec![],
      token_lifetime: 3600,
      allowed_origins: ["http://localhost:3000".to_string()].to_vec(),
      domain: "localhost:3002".to_string(),
    }
  }
}

pub fn load(name: &str) -> Config {
  confy::load::<Config>(name).unwrap()
}