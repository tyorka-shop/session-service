mod session_service;

pub use session_service::session_service_server as server;

pub use session_service::{
    VerifyRequest, VerifyResponse, TokenStatus,
};

use tonic::Request;

use session_service::{
    session_service_client::SessionServiceClient,
};

pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!("description.bin");

#[derive(Debug)]
pub enum VerifyError {
    Connect,
    Request,
    Unautorized,
}

impl TokenStatus {
    fn from_num(value: i32) -> Self {
        match value {
            0 => TokenStatus::Ok,
            1 => TokenStatus::Expired,
            2 => TokenStatus::NotGrunted,
            _ => TokenStatus::Invalid,
        }
    }
}

pub struct Client {
    pub url: String,
}

impl Client {
    pub async fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }

    pub async fn verify(&self, token: &str) -> Result<String, VerifyError> {
        let mut client = SessionServiceClient::connect(self.url.to_owned())
            .await
            .map_err(|_| VerifyError::Connect)?;

        let request = Request::new(VerifyRequest {
            token: token.to_string(),
        });

        let response = client
            .verify(request)
            .await
            .map_err(|_| VerifyError::Request)?
            .into_inner();

        match TokenStatus::from_num(response.status) {
            TokenStatus::Ok => Ok(response.email),
            _ => Err(VerifyError::Unautorized),
        }
    }
}
