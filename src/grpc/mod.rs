use std::net::{SocketAddr, Ipv4Addr};

use log::info;
use tonic::transport::Server;
use warp::Future;

use session_service_impl::{SessionService};
use session_service_proto::{server::{SessionServiceServer}, FILE_DESCRIPTOR_SET};

pub mod session_service_impl;

pub fn make_server(
    cfg: config::Config,
) -> impl Future<Output = Result<(), tonic::transport::Error>> {
    let session_service = SessionService {
        secret: cfg.secret,
        granted_emails: cfg.granted_emails,
    };

    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), cfg.grpc_port.parse::<u16>().unwrap());

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build()
        .unwrap();

    info!("GRPC listening on 50051");

    Server::builder()
        .add_service(SessionServiceServer::new(session_service))
        .add_service(reflection_service)
        .serve(addr)
}

#[cfg(test)]
mod test_verify {
    
    use session_service_proto::{TokenStatus, VerifyRequest, server::SessionService as SSI};
    use super::session_service_impl::SessionService;
    use tonic::Request;

    const EMAIL: &str = "john@doe.com";
    const SECRET: &str = "secret";

    async fn make_test_service() -> SessionService {
        SessionService {
            secret: SECRET.to_string(),
            granted_emails: vec![EMAIL.to_string()],
        }
    }

    async fn verify(token: &str, status: TokenStatus) {
        let service = make_test_service().await;

        let resp = service
            .verify(Request::new(VerifyRequest {
                token: token.to_string(),
            }))
            .await;
        assert!(resp.is_ok());
        let resp = resp.unwrap().into_inner();
        assert_eq!(resp.status, status as i32);
    }

    #[tokio::test]
    async fn invalid() {
        verify("wrong_token", TokenStatus::Invalid).await;
    }

    #[tokio::test]
    async fn not_grunted() {
        let token = crate::token::create("john@example.com".into(), SECRET.as_bytes(), 60).unwrap();
        verify(&token, TokenStatus::NotGrunted).await;
    }

    #[tokio::test]
    async fn expired() {
        let token = crate::token::create(EMAIL.into(), SECRET.as_bytes(), -60).unwrap();
        verify(&token, TokenStatus::Expired).await;
    }

    #[tokio::test]
    async fn valid() {
        let token = crate::token::create(EMAIL.into(), SECRET.as_bytes(), 60).unwrap();
        verify(&token, TokenStatus::Ok).await;
    }
}
