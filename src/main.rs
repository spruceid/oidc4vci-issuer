use oidc4vci_rs::CredentialFormat;
use rocket::{
    catchers,
    fs::{relative, FileServer},
    launch, routes,
    serde::json::Json,
};
use rocket_dyn_templates::Template;
use ssi::jwk::{Params, JWK};

use oidc4vci_issuer::*;

#[rocket::post("/token", data = "<query>")]
fn post_token_default_op_state(
    query: rocket::form::Form<token::TokenQueryParams>,
    nonces: &rocket::State<redis::Client>,
    metadata: &rocket::State<types::Metadata>,
    interface: &rocket::State<oidc4vci_rs::SSI>,
) -> Result<rocket::serde::json::Json<serde_json::Value>, error::Error> {
    token::post_token(
        query.into_inner(),
        nonces.inner(),
        metadata.inner(),
        interface.inner(),
        oidc4vci_rs::verify_preauthz_code,
    )
    .map(Json)
}

#[rocket::post("/credential", data = "<credential_request>")]
pub async fn post_credential_open_badge(
    credential_request: rocket::serde::json::Json<oidc4vci_rs::CredentialRequest>,
    token: authorization::AuthorizationToken,
    metadata: &rocket::State<types::Metadata>,
    config: &rocket::State<types::Config>,
    interface: &rocket::State<oidc4vci_rs::SSI>,
) -> Result<rocket::serde::json::Json<serde_json::Value>, error::Error> {
    credential::post_credential(
        credential_request.into_inner(),
        &token,
        metadata.inner(),
        config.inner(),
        interface.inner(),
        credential::OIDC4VCIVerifyCredentialRequest {},
        &credential::post_credential_open_badge_json,
        None::<oidc4vci_rs::ExternalFormatVerifier>,
        credential::default_unknown_credential_handler,
    )
    .await
    .map(Json)
}

#[launch]
fn rocket() -> _ {
    dotenv::dotenv().ok();

    let issuer = std::env::var("ISSUER").expect("Failed to load ISSUER");
    let jwk = std::env::var("JWK").expect("Failed to load JWK");
    let password = std::env::var("JWE_SECRET").expect("Failed to load JWE_SECRET");

    let did_method = std::env::var("DID_METHOD").unwrap_or_else(|_| "jwk".to_string());
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());

    let jwk: JWK = serde_json::from_str(&jwk).expect("Failed to parse JWK");
    let algorithm = match &jwk.params {
        Params::OKP(_) => Ok(ssi::jwk::Algorithm::EdDSA),
        Params::EC(ec) => match ec.curve.as_ref().ok_or("Missing curve").unwrap().as_str() {
            "P-256" => Ok(ssi::jwk::Algorithm::ES256),
            "secp256k1" => Ok(ssi::jwk::Algorithm::ES256K),
            _ => Err("Unsupported curve"),
        },
        _ => Err("The provided JWK is currently not supported."),
    }
    .unwrap();

    let interface = oidc4vci_rs::SSI::new(jwk, algorithm, &password);

    let method: oidc4vci_issuer::types::Method =
        serde_json::from_str(&format!("\"{}\"", &did_method))
            .expect("Failed to parse DID_METHOD, allowed values: 'key', 'jwk', or 'web'.");

    let metadata = oidc4vci_issuer::types::Metadata {
        audience: issuer.to_owned(),
        credential_types: vec!["OpenBadgeCredential".into()],
        formats: vec![CredentialFormat::LDP, CredentialFormat::JWT],
    };

    let config = oidc4vci_issuer::Config {
        issuer,
        method,
        did_method,
    };

    let client = redis::Client::open(redis_url).unwrap();

    let routes = match &config.method {
        oidc4vci_issuer::types::Method::Key | oidc4vci_issuer::types::Method::Jwk => routes![
            development::index,
            development::preauth,
            post_credential_open_badge,
            post_token_default_op_state,
            configuration::openid_configuration,
            configuration::oauth_authorization_server,
            configuration::verifiable_credentials_server,
            configuration::jwks,
        ],
        oidc4vci_issuer::types::Method::Web => routes![
            development::index,
            development::preauth,
            post_credential_open_badge,
            post_token_default_op_state,
            configuration::openid_configuration,
            configuration::oauth_authorization_server,
            configuration::verifiable_credentials_server,
            configuration::jwks,
            configuration::did_web,
        ],
    };

    rocket::build()
        .manage(interface)
        .manage(metadata)
        .manage(config)
        .manage(client)
        .mount("/", routes)
        .mount("/static", FileServer::from(relative!("static")))
        .register("/", catchers![error::not_found, error::default_catcher])
        .attach(Template::fairing())
}
