use oidc4vci_rs::SSI;
use rocket::{get, serde::json::Json, State};
use serde_json::{json, Value};

use crate::Config;

#[get("/.well-known/openid-configuration")]
pub fn openid(config: &State<Config>) -> Json<Value> {
    Json(json!({
       "issuer": config.issuer,
       "credential_endpoint": format!("{}/credential", config.issuer),
       "token_endpoint": format!("{}/token", config.issuer),
       "jwks_uri": format!("{}/jwks", config.issuer),
       "grant_types_supported": [
          "urn:ietf:params:oauth:grant-type:pre-authorized_code"
       ],
       "credentials_supported": {
          "OpenBadgeCredential": {
             "formats": {
                "jwt_vc": {
                   "types": [
        "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential",
        "https://w3id.org/ngi/OpenBadgeExtendedCredential"
                   ],
                   "binding_methods_supported": [
                      "did"
                   ],
                   "cryptographic_suites_supported": [
                      "ES256"
                   ]
                }
             }
          }
       }
    }))
}

#[get("/jwks")]
pub fn jwks(interface: &State<SSI>) -> Json<Value> {
    let jwk = interface.jwk.to_public();

    Json(json!({
        "keys" : vec![jwk],
    }))
}
