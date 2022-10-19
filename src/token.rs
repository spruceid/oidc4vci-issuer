use lazy_static::lazy_static;
use oidc4vci_rs::{AccessTokenParams, OIDCError, PreAuthzCode, TokenErrorType, TokenType, SSI};
use rocket::{form::Form, post, serde::json::Json, FromForm, State};
use serde_json::Value;

use crate::types::Metadata;

#[derive(FromForm)]
pub struct TokenQueryParams {
    grant_type: String,

    #[field(name = "pre-authorized_code")]
    pre_authz_code: String,

    pin: Option<String>,
}

lazy_static! {
    static ref SUPPORTED_TYPES: Vec<String> =
        vec!["urn:ietf:params:oauth:grant-type:pre-authorized_code".into(),];
}

#[post("/token", data = "<query>")]
pub fn post_token(
    query: Form<TokenQueryParams>,
    nonces: &State<redis::Client>,
    metadata: &State<Metadata>,
    interface: &State<SSI>,
) -> Result<Json<Value>, crate::error::Error> {
    let TokenQueryParams {
        grant_type,
        pre_authz_code,
        pin,
    } = query.into_inner();

    if !SUPPORTED_TYPES.contains(&grant_type) {
        let err: OIDCError = TokenErrorType::InvalidGrant.into();
        return Err(err.into());
    }

    let PreAuthzCode {
        credential_type,
        extra,
        ..
    } = oidc4vci_rs::verify_preauthz_code(
        &pre_authz_code,
        pin.as_deref(),
        metadata.inner(),
        interface.inner(),
    )?;

    let nonce = extra.get("nonce");
    if nonce.is_none() {
        let err: OIDCError = TokenErrorType::InvalidGrant.into();
        return Err(err.into());
    }

    let nonce = nonce.unwrap().as_str();
    let mut conn = nonces.get_connection().map_err(|_| OIDCError::default())?;

    let nonce_used: bool = redis::cmd("EXISTS")
        .arg(nonce)
        .query(&mut conn)
        .map_err(|_| OIDCError::default())?;

    if nonce_used {
        let err: OIDCError = TokenErrorType::InvalidGrant.into();
        return Err(err.into());
    } else {
        redis::cmd("SETEX")
            .arg(nonce)
            .arg("300")
            .arg(nonce)
            .query(&mut conn)
            .map_err(|_| OIDCError::default())?;
    }

    let credential_type = credential_type.to_single().unwrap();

    let token_response = oidc4vci_rs::generate_access_token(
        AccessTokenParams::new(
            vec![credential_type.to_string()],
            None,
            &TokenType::Bearer,
            84600,
        ),
        interface.inner(),
    )?;

    Ok(Json(serde_json::to_value(token_response).unwrap()))
}
