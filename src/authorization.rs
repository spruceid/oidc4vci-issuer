use oidc4vci_rs::{AuthorizationErrorType, SSI};
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
    type Error = oidc4vci_rs::OIDCError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let token = request.headers().get_one("Authorization");

        match token {
            Some(token) => {
                if !token.starts_with("Bearer ") {
                    request.local_cache::<Vec<oidc4vci_rs::OIDCError>, _>(|| {
                        vec![AuthorizationErrorType::InvalidToken.into()]
                    });

                    return Outcome::Failure((
                        Status::Unauthorized,
                        AuthorizationErrorType::InvalidToken.into(),
                    ));
                }

                let token = token[7..].to_string();
                let interface = request.rocket().state::<SSI>().unwrap();
                match oidc4vci_rs::verify_access_token(&token, interface) {
                    Ok(_) => Outcome::Success(AuthorizationToken(token)),
                    Err(_) => {
                        request.local_cache::<Vec<oidc4vci_rs::OIDCError>, _>(|| {
                            vec![AuthorizationErrorType::InvalidToken.into()]
                        });

                        Outcome::Failure((
                            Status::BadRequest,
                            AuthorizationErrorType::InvalidToken.into(),
                        ))
                    }
                }
            }
            None => {
                request.local_cache::<Vec<oidc4vci_rs::OIDCError>, _>(|| {
                    vec![AuthorizationErrorType::InvalidToken.into()]
                });

                Outcome::Failure((
                    Status::Unauthorized,
                    AuthorizationErrorType::InvalidToken.into(),
                ))
            }
        }
    }
}
