use oidc4vci_rs::TokenErrorType;
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
                    return Outcome::Failure((
                        Status::Unauthorized,
                        TokenErrorType::InvalidRequest.into(),
                    ));
                }

                Outcome::Success(AuthorizationToken(token[7..].to_string()))
            }
            None => Outcome::Failure((
                Status::Unauthorized,
                TokenErrorType::UnauthorizedClient.into(),
            )),
        }
    }
}
