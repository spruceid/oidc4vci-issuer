use lazy_static::lazy_static;
use oidc4vci_rs::{AccessTokenParams, OIDCError, PreAuthzCode, TokenErrorType, TokenType, SSI};
use rocket::form::FromForm;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::{error::Error, types::Metadata};

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

#[derive(Debug, FromForm, Deserialize, Serialize)]
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
pub fn post_token<T: ToHashMap, F>(
    query: TokenQueryParams<T>,
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
        op_state,
    } = query;

    let mut op_state_map = op_state
        .map(|x| x.to_hashmap())
        .unwrap_or_else(|| HashMap::new());

    println!("token 1");

    if !SUPPORTED_TYPES.contains(&grant_type) {
        let err: OIDCError = TokenErrorType::InvalidGrant.into();
        return Err(err.into());
    }

    println!("token 2: verify_preauthz_code");

    let PreAuthzCode {
        credential_type,
        extra,
        ..
    } = verify_preauthz_code(
        &pre_authz_code,
        pin.as_deref(),
        metadata,
        interface,
    )?;

    if let Some(extra_op_state) = extra.get("op_state") {
        match extra_op_state {
            serde_json::Value::Object(extra_op_state_map) => {
                for (op_state_key, op_state_val) in extra_op_state_map.into_iter() {
                    op_state_map.insert(op_state_key.clone(), op_state_val.clone());
                }
            },
            _ => {
                println!("/token op_state dropped because not a JSON map: {:?}", extra_op_state);
            },
        }
    }

    println!("token 3");

    let nonce = extra.get("nonce");
    if nonce.is_none() {
        let err: OIDCError = TokenErrorType::InvalidGrant.into();
        return Err(err.into());
    }

    println!("token 4");

    let nonce = nonce.unwrap().as_str();
    let mut conn = nonces.get_connection().map_err(|_| OIDCError::default())?;

    println!("token 5");

    let nonce_used: bool = redis::cmd("EXISTS")
        .arg(nonce)
        .query(&mut conn)
        .map_err(|_| OIDCError::default())?;

    println!("token 6");

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

    println!("token 7");

    let credential_type = credential_type.to_single().unwrap();

    let op_state_map_opt = if op_state_map.is_empty() {
        None
    } else {
        Some(op_state_map)
    };

    let token_response = oidc4vci_rs::generate_access_token(
        AccessTokenParams::new(
            vec![credential_type.to_string()],
            op_state_map_opt,
            &TokenType::Bearer,
            84600,
        ),
        interface,
    )?;

    println!("token 8");

    Ok(serde_json::to_value(token_response).unwrap())
}
