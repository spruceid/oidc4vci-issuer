use std::io::Cursor;

use oidc4vci_rs::{CredentialRequestErrorType, OIDCError, OIDCErrorType, TokenErrorType};
use rocket::{
    catch,
    http::{ContentType, Status},
    response::Responder,
    serde::json::Json,
    Request, Response,
};

#[derive(Debug)]
pub struct Error(pub OIDCError);

#[rocket::async_trait]
impl<'r, 'o: 'r> Responder<'r, 'o> for Error {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let body = serde_json::to_string(&self.0).unwrap();

        Response::build()
            .status(match self.0.ty {
                OIDCErrorType::Authorization(_) => Status::Unauthorized,
                OIDCErrorType::Token(ty) => match ty {
                    TokenErrorType::InvalidRequest => Status::BadRequest,
                    TokenErrorType::InvalidClient => Status::BadRequest,
                    TokenErrorType::InvalidGrant => Status::BadRequest,
                    TokenErrorType::UnauthorizedClient => Status::BadRequest,
                    TokenErrorType::UnsupportedGrantType => Status::BadRequest,
                    TokenErrorType::InvalidScope => Status::BadRequest,
                    _ => Status::BadRequest,
                },
                OIDCErrorType::CredentialRequest(ty) => match ty {
                    CredentialRequestErrorType::InvalidOrMissingProof => Status::BadRequest,
                    CredentialRequestErrorType::InvalidRequest => Status::BadRequest,
                    CredentialRequestErrorType::UnsupportedType => Status::BadRequest,
                    CredentialRequestErrorType::UnsupportedFormat => Status::BadRequest,
                    CredentialRequestErrorType::InvalidCredential => Status::BadRequest,
                    _ => Status::BadRequest,
                },
                _ => Status::BadRequest,
            })
            .header(ContentType::JSON)
            .sized_body(body.len(), Cursor::new(body))
            .ok()
    }
}

impl From<OIDCError> for Error {
    fn from(error: OIDCError) -> Self {
        Self(error)
    }
}

#[catch(404)]
pub fn not_found(request: &Request) -> Json<OIDCError> {
    Json(OIDCError::default().with_desc("route not found"))
}

#[catch(default)]
pub fn default_catcher(request: &Request) -> Json<OIDCError> {
    if let Some(err) = request.local_cache::<Vec<OIDCError>, _>(Vec::new).get(0) {
        Json(err.to_owned())
    } else {
        Json(OIDCError::default())
    }
}
