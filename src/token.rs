use oidc4vci_rs::{AccessTokenParams, PreAuthzCode, TokenType, SSI};
use rocket::{post, serde::json::Json, FromForm, State};
use serde_json::Value;

use crate::Metadata;

#[derive(FromForm)]
pub struct QueryParams {
    grant_type: String,

    #[field(name = "pre-authorized_code")]
    pre_authz_code: String,
}

#[post("/token?<query..>")]
pub fn post(query: QueryParams, metadata: &State<Metadata>, interface: &State<SSI>) -> Json<Value> {
    let QueryParams {
        grant_type,
        pre_authz_code,
    } = query;

    // TODO: replace by grant_type checking
    assert_eq!(
        grant_type,
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    );

    let PreAuthzCode {
        credential_type, ..
    } = oidc4vci_rs::verify_preauthz_code(&pre_authz_code, metadata.inner(), interface.inner())
        .unwrap();

    let credential_type = credential_type.to_single().unwrap();

    let token_response = oidc4vci_rs::generate_access_token(
        AccessTokenParams::new(credential_type, &TokenType::Bearer, 84600),
        interface.inner(),
    )
    .unwrap();

    Json(serde_json::to_value(token_response).unwrap())
}
