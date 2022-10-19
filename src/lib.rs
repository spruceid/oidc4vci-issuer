//! OIDC4VCI-issuer Rust Library

#![warn(unreachable_pub, unused_extern_crates, unused_import_braces, unused_lifetimes, unused_qualifications)]
#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

mod authorization;
pub use authorization::AuthorizationToken;

mod configuration;
pub use configuration::{jwks, oauth_authorization_server, openid_configuration, verifiable_credentials_server};

mod credential;
pub use credential::post_credential;

mod development;
pub use development::{PreAuthQueryParams, index, preauth};

mod error;
pub use error::default_catcher;

mod token;
pub use token::{TokenQueryParams, post_token};

mod types;
pub use types::{Config, Metadata};

