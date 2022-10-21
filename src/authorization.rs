use oidc4vci_rs::{AuthorizationErrorType, OIDCError, SSI};
use rocket::{
    async_trait,
    http::Status,
    outcome::Outcome,
    request::{self, FromRequest},
    Request,
};

pub struct AuthorizationToken(pub String);

#[async_trait]
impl<'r> FromRequest<'r> for AuthorizationToken {
    type Error = OIDCError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let token = request.headers().get_one("Authorization");

        match token {
            Some(token) => {
                if !token.starts_with("Bearer ") {
                    let err: OIDCError = AuthorizationErrorType::InvalidToken.into();

                    request.local_cache::<Vec<oidc4vci_rs::OIDCError>, _>(|| {
                        vec![err
                            .clone()
                            .with_desc("Authorization must contain a Bearer token")]
                    });

                    return Outcome::Failure((Status::Unauthorized, err));
                }

                let token = token[7..].to_string();
                let interface = request.rocket().state::<SSI>().unwrap();
                match oidc4vci_rs::verify_access_token(&token, interface) {
                    Ok(_) => Outcome::Success(AuthorizationToken(token)),
                    Err(_) => {
                        let err: OIDCError = AuthorizationErrorType::InvalidToken.into();

                        request.local_cache::<Vec<oidc4vci_rs::OIDCError>, _>(|| {
                            vec![err.clone().with_desc("Bearer token is invalid")]
                        });

                        Outcome::Failure((Status::BadRequest, err))
                    }
                }
            }
            None => {
                let err: OIDCError = AuthorizationErrorType::InvalidToken.into();
                request.local_cache::<Vec<oidc4vci_rs::OIDCError>, _>(|| {
                    vec![err
                        .clone()
                        .with_desc("Authorization header must be present")]
                });

                Outcome::Failure((Status::Unauthorized, err))
            }
        }
    }
}
