use lazy_static::lazy_static;
use oidc4vci_rs::CredentialFormat;
use serde::{Deserialize, Serialize};
use ssi::did::DIDMethods;

lazy_static! {
    pub static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(Box::new(did_method_key::DIDKey));
        methods.insert(Box::new(did_jwk::DIDJWK));
        methods.insert(Box::new(did_web::DIDWeb));
        methods
    };
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
pub enum Method {
    #[serde(rename = "key")]
    Key,

    #[serde(rename = "jwk")]
    Jwk,

    #[serde(rename = "web")]
    Web,
}

pub struct Config {
    pub issuer: String,
    pub method: Method,
    pub did_method: String,
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
