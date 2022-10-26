//! OIDC4VCI-issuer Rust Library

#![warn(unreachable_pub, unused_extern_crates, unused_import_braces, unused_lifetimes, unused_qualifications)]
#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

pub mod authorization;
pub use authorization::AuthorizationToken;

pub mod configuration;
pub use configuration::{jwks, oauth_authorization_server, openid_configuration, verifiable_credentials_server};

pub mod credential;
pub use credential::post_credential;

pub mod development;
pub use development::{PreAuthQueryParams, index, preauth};

pub mod error;
pub use error::{Error, default_catcher};

pub mod token;
pub use token::{TokenQueryParams, post_token};

pub mod types;
pub use types::{DID_METHODS, Config, Method, Metadata};

