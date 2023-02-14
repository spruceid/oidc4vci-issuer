use lazy_static::lazy_static;
use oidc4vci_rs::{
    AccessTokenParams, OIDCError, PreAuthzCode, TokenErrorType, TokenQueryParams, TokenType, SSI,
};
use rocket::form::FromForm;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::{error::Error, types::Metadata};

#[derive(Debug, FromForm, Deserialize, Serialize)]
pub struct TokenRequest {
    #[serde(flatten)]
    pub inner: TokenQueryParams,
    pub authorization_pending: bool,
}

pub trait ToHashMap: std::fmt::Debug {
    fn to_hashmap(&self) -> HashMap<String, Value>;
}

#[derive(Debug, FromForm, Deserialize, Serialize)]
pub struct DefaultOpState {
    op_state: Option<String>,
}

impl ToHashMap for DefaultOpState {
    fn to_hashmap(&self) -> HashMap<String, Value> {
        HashMap::new()
    }
}

lazy_static! {
    static ref SUPPORTED_TYPES: Vec<String> =
        vec!["urn:ietf:params:oauth:grant-type:pre-authorized_code".into(),];
}

pub fn post_token<F>(
    query: TokenQueryParams,
    nonces: &redis::Client,
    metadata: &Metadata,
    interface: &SSI,
    verify_preauthz_code: F,
) -> Result<Value, Error>
where
    F: FnOnce(&str, Option<&str>, &Metadata, &SSI) -> Result<PreAuthzCode, OIDCError>,
{
    let TokenQueryParams {
        grant_type,
        pre_authz_code,
        pin,
    } = query;

    if !SUPPORTED_TYPES.contains(&grant_type) {
        let err: OIDCError = TokenErrorType::InvalidGrant.into();
        return Err(err.into());
    }

    let PreAuthzCode {
        credential_type,
        extra,
        ..
    } = verify_preauthz_code(&pre_authz_code, pin.as_deref(), metadata, interface)?;

    let op_state: HashMap<String, Value> = match extra.get("op_state") {
        Some(op_state) => match op_state.as_object() {
            Some(_) => serde_json::from_value(op_state.to_owned()).unwrap(),
            None => HashMap::new(),
        },
        None => HashMap::new(),
    };

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

    let token_response = oidc4vci_rs::generate_access_token(
        AccessTokenParams::new(credential_type, Some(op_state), &TokenType::Bearer, 84600),
        interface,
    )?;

    Ok(serde_json::to_value(token_response).unwrap())
}
