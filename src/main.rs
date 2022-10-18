use lazy_static::lazy_static;
use oidc4vci_rs::CredentialFormat;
use rocket::{catchers, launch, routes};
use rocket_dyn_templates::Template;
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
        methods.insert(&did_method_jwk::DIDJWK);
        methods
    };
}

pub struct Config {
    issuer: String,
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

#[launch]
fn rocket() -> _ {
    dotenv::dotenv().ok();

    let issuer = std::env::var("ISSUER").expect("Failed to load ISSUER");
    let jwk = std::env::var("JWK").expect("Failed to load JWK");
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());

    let interface = oidc4vci_rs::SSI::new(
        serde_json::from_str(&jwk).expect("Failed to parse JWK"),
        ssi::jwk::Algorithm::EdDSA,
    );

    let metadata = Metadata {
        audience: issuer.to_owned(),
        credential_types: vec!["OpenBadgeCredential".into()],
        formats: vec![CredentialFormat::JWT],
    };

    let config = Config { issuer };

    let client = redis::Client::open(redis_url).unwrap();

    rocket::build()
        .manage(interface)
        .manage(metadata)
        .manage(config)
        .manage(client)
        .mount(
            "/",
            routes![
                development::index,
                development::preauth,
                credential::post,
                token::post,
                configuration::verifiable_credentials_server,
                configuration::jwks,
            ],
        )
        .register("/", catchers![error::default_catcher])
        .attach(Template::fairing())
}
