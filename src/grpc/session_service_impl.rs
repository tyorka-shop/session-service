use super::session_service::session_service_server;
use super::session_service::{TokenStatus, VerifyRequest, VerifyResponse};
use crate::token::{VerifyError};
use tonic::{Request, Response, Status};

pub use super::session_service::session_service_server::SessionServiceServer;

#[derive(Debug)]
pub struct SessionService {
    pub secret: String,
    pub granted_emails: Vec<String>,
}

#[tonic::async_trait]
impl session_service_server::SessionService for SessionService {
    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let token = request.into_inner().token;
        let status = match crate::token::verify(&token, &self.secret.as_bytes(), &self.granted_emails) {
            Ok(_) => TokenStatus::Ok,
            Err(e) => match e {
                VerifyError::Expired => TokenStatus::Expired,
                VerifyError::NotGrunted => TokenStatus::NotGrunted,
                _ => TokenStatus::Invalid,
            },
        };

        Ok(tonic::Response::new(VerifyResponse {
            status: status as i32,
        }))
    }
}
