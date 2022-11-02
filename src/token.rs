use lazy_static::lazy_static;
use oidc4vci_rs::{AccessTokenParams, OIDCError, PreAuthzCode, TokenErrorType, TokenType, SSI};
use rocket::form::FromForm;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::{error::Error, types::Metadata};

pub trait ToHashMap {
    fn to_hashmap(&self) -> HashMap<String, Value>;
}

#[derive(FromForm, Deserialize, Serialize)]
pub struct DefaultOpState {
    op_state: Option<String>,
}

impl ToHashMap for DefaultOpState {
    fn to_hashmap(&self) -> HashMap<String, Value> {
        HashMap::new()
    }
}

#[derive(FromForm, Deserialize, Serialize)]
pub struct TokenQueryParams<T: ToHashMap> {
    pub grant_type: String,

    #[field(name = "pre-authorized_code")]
    #[serde(rename = "pre-authorized_code")]
    pub pre_authz_code: String,

    pub pin: Option<String>,

    pub op_state: Option<T>,
}

lazy_static! {
    static ref SUPPORTED_TYPES: Vec<String> =
        vec!["urn:ietf:params:oauth:grant-type:pre-authorized_code".into(),];
}

// #[post("/token", data = "<query>")]
pub fn post_token<T: ToHashMap>(
    TokenQueryParams {
        grant_type,
        pre_authz_code,
        pin,
        op_state,
    }: TokenQueryParams<T>,
    nonces: &redis::Client,
    metadata: &Metadata,
    interface: &SSI,
) -> Result<Value, Error> {
    if !SUPPORTED_TYPES.contains(&grant_type) {
        let err: OIDCError = TokenErrorType::InvalidGrant.into();
        return Err(err.into());
    }

    let PreAuthzCode {
        credential_type,
        extra,
        ..
    } = oidc4vci_rs::verify_preauthz_code(&pre_authz_code, pin.as_deref(), metadata, interface)?;

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
            op_state.map(|x| x.to_hashmap()),
            &TokenType::Bearer,
            84600,
        ),
        interface,
    )?;

    Ok(serde_json::to_value(token_response).unwrap())
}
