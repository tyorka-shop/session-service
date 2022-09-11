use crate::token::VerifyError;
use session_service_grpc::{TokenStatus, VerifyRequest, VerifyResponse};
use tonic::{Request, Response, Status};

#[derive(Debug)]
pub struct SessionService {
    pub secret: String,
    pub granted_emails: Vec<String>,
}

#[tonic::async_trait]
impl session_service_grpc::server::SessionService for SessionService {
    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let token = request.into_inner().token;
        let (status, email) =
            match crate::token::verify(&token, &self.secret.as_bytes(), &self.granted_emails) {
                Ok(email) => (TokenStatus::Ok, Some(email)),
                Err(e) => match e {
                    VerifyError::Expired => (TokenStatus::Expired, None),
                    VerifyError::NotGrunted => (TokenStatus::NotGrunted, None),
                    _ => (TokenStatus::Invalid, None),
                },
            };

        Ok(Response::new(VerifyResponse {
            status: status as i32,
            email: email.unwrap_or_default(),
        }))
    }
}
