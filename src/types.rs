use lazy_static::lazy_static;
use oidc4vci_rs::CredentialFormat;
// use rocket::{catchers, launch, routes};
// use rocket_dyn_templates::Template;
use ssi::did::DIDMethods;

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
    pub issuer: String,
}

pub struct Metadata {
    pub audience: String,
    pub credential_types: Vec<String>,
    pub formats: Vec<CredentialFormat>,
}

impl oidc4vci_rs::Metadata for Metadata {
    fn get_audience(&self) -> &str {
        &self.audience
    }

    fn get_credential_types(&self) -> std::slice::Iter<'_, String> {
        self.credential_types.iter()
    }

    fn get_allowed_formats(&self, _: &str) -> std::slice::Iter<'_, CredentialFormat> {
        self.formats.iter()
    }
}

