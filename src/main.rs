use oidc4vci_rs::CredentialFormat;
use rocket::{
    catchers,
    fs::{relative, FileServer},
    launch, routes,
};
use rocket_dyn_templates::Template;
use ssi::jwk::{Params, JWK};

mod authorization;
mod configuration;
mod credential;
mod development;
mod error;
mod token;
mod types;

#[rocket::post("/token", data = "<query>")]
fn post_token_default_op_state(
    query: rocket::form::Form<token::TokenQueryParams<token::DefaultOpState>>,
    nonces: &rocket::State<redis::Client>,
    metadata: &rocket::State<types::Metadata>,
    interface: &rocket::State<oidc4vci_rs::SSI>,
) -> Result<rocket::serde::json::Json<serde_json::Value>, error::Error> {
    token::post_token(query, nonces, metadata, interface)
}

#[rocket::post("/credential", data = "<credential_request>")]
pub async fn post_credential_open_badge(
    credential_request: rocket::serde::json::Json<oidc4vci_rs::CredentialRequest>,
    token: authorization::AuthorizationToken,
    metadata: &rocket::State<types::Metadata>,
    config: &rocket::State<types::Config>,
    interface: &rocket::State<oidc4vci_rs::SSI>,
) -> Result<rocket::serde::json::Json<serde_json::Value>, error::Error> {
    credential::post_credential(credential_request, token, metadata, config, interface, |id, issuer, iat, exp, did| {
        serde_json::json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://purl.imsglobal.org/spec/ob/v3p0/context.json"
            ],
            "id": id,
            "type": [
                "VerifiableCredential",
                "OpenBadgeCredential",
            ],
            "name": "JFF x vc-edu PlugFest 2 Interoperability",
            "issuer": {
                "type": ["Profile"],
                "id": issuer,
                "name": "Jobs for the Future (JFF)",
                "url": "https://www.jff.org/",
                "image": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png"
            },
            "issuanceDate": iat,
            "expirationDate": exp,

            "credentialSubject": {
                "type": ["AchievementSubject"],
                "id": did,
                "achievement": {
                    "id": "urn:uuid:bd6d9316-f7ae-4073-a1e5-2f7f5bd22922",
                    "type": ["Achievement"],
                    "name": "JFF x vc-edu PlugFest 2 Interoperability",
                    "description": "This credential solution supports the use of OBv3 and w3c Verifiable Credentials and is interoperable with at least two other solutions.  This was demonstrated successfully during JFF x vc-edu PlugFest 2.",
                    "criteria": {
                        "narrative": "Solutions providers earned this badge by demonstrating interoperability between multiple providers based on the OBv3 candidate final standard, with some additional required fields. Credential issuers earning this badge successfully issued a credential into at least two wallets.  Wallet implementers earning this badge successfully displayed credentials issued by at least two different credential issuers."
                    },
                    "image": {
                        "id": "https://w3c-ccg.github.io/vc-ed/plugfest-2-2022/images/JFF-VC-EDU-PLUGFEST2-badge-image.png",
                        "type": "Image"
                    }
                }
            }
        })
    }).await
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

    let method: oidc4vci_issuer::types::Method = serde_json::from_str(&format!("\"{}\"", &did_method))
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
            // credential::post_credential,
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
            // credential::post_credential,
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
