use lazy_static::lazy_static;
use oidc4vci_rs::CredentialFormat;
use rocket::{catchers, launch, routes};
use rocket_dyn_templates::Template;
use serde::{Deserialize, Serialize};
use ssi::did::DIDMethods;

mod authorization;
mod configuration;
mod credential;
mod development;
mod error;
mod token;

lazy_static! {
    pub static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(&did_method_key::DIDKey);
        methods.insert(&did_jwk::DIDJWK);
        methods.insert(&did_web::DIDWeb);
        methods
    };
}

pub struct Config {
    issuer: String,
    method: Method,
    did_method: String,
}

pub struct Metadata {
    audience: String,
    credential_types: Vec<String>,
    formats: Vec<CredentialFormat>,
}

impl oidc4vci_rs::Metadata for Metadata {
    fn get_audience(&self) -> &str {
        &self.audience
    }

    fn get_credential_types(&self) -> std::slice::Iter<'_, String> {
        self.credential_types.iter()
    }

    fn get_allowed_formats(&self, _: &str) -> std::slice::Iter<'_, oidc4vci_rs::CredentialFormat> {
        self.formats.iter()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
enum Method {
    #[serde(rename = "key")]
    Key,

    #[serde(rename = "jwk")]
    Jwk,

    #[serde(rename = "web")]
    Web,
}

#[launch]
fn rocket() -> _ {
    dotenv::dotenv().ok();

    let issuer = std::env::var("ISSUER").expect("Failed to load ISSUER");
    let jwk = std::env::var("JWK").expect("Failed to load JWK");
    let did_method = std::env::var("DID_METHOD").unwrap_or_else(|_| "jwk".to_string());
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());

    let interface = oidc4vci_rs::SSI::new(
        serde_json::from_str(&jwk).expect("Failed to parse JWK"),
        ssi::jwk::Algorithm::EdDSA,
    );

    let method: Method = serde_json::from_str(&format!("\"{}\"", &did_method))
        .expect("Failed to parse DID_METHOD, allowed values: 'key', 'jwk', or 'web'.");

    let metadata = Metadata {
        audience: issuer.to_owned(),
        credential_types: vec!["OpenBadgeCredential".into()],
        formats: vec![CredentialFormat::LDP, CredentialFormat::JWT],
    };

    let config = Config {
        issuer,
        method,
        did_method,
    };

    let client = redis::Client::open(redis_url).unwrap();

    let routes = match &config.method {
        Method::Key | Method::Jwk => routes![
            development::index,
            development::preauth,
            credential::post,
            token::post,
            configuration::openid_configuration,
            configuration::oauth_authorization_server,
            configuration::verifiable_credentials_server,
            configuration::jwks,
        ],
        Method::Web => routes![
            development::index,
            development::preauth,
            credential::post,
            token::post,
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
        .register("/", catchers![error::default_catcher])
        .attach(Template::fairing())
}
