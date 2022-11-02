//! OIDC4VCI-issuer Rust Library

#![warn(
    unreachable_pub,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications
)]
#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

pub mod authorization;
pub use authorization::AuthorizationToken;

pub mod configuration;
pub use configuration::{
    jwks, oauth_authorization_server, openid_configuration, verifiable_credentials_server,
};

pub mod credential;
pub use credential::{post_credential, post_credential_mult};

pub mod development;
pub use development::{index, preauth, PreAuthQueryParams};

pub mod error;
pub use error::{default_catcher, Error};

pub mod token;
pub use token::{post_token, ToHashMap, TokenQueryParams};

pub mod types;
pub use types::{Config, Metadata, Method, DID_METHODS};
