use async_trait::async_trait;
use chrono::{Duration, DurationRound, Utc};
use oidc4vci_rs::{generate_credential_response, CredentialRequest, SSI};
use serde_json::Value;
use ssi::{
    did::Source,
    jsonld::ContextLoader,
    vc::{
        get_verification_methods_for_purpose, LinkedDataProofOptions, ProofPurpose, VCDateTime, URI,
    },
};
use uuid::Uuid;

use crate::{
    authorization::AuthorizationToken,
    types::{Config, Metadata, DID_METHODS},
};

pub fn post_credential_open_badge_json(
    id: String,
    issuer: String,
    iat: VCDateTime,
    exp: VCDateTime,
    did: String,
) -> Value {
    let achievement_id = Uuid::new_v4().to_string();
    let achievement_id = format!("urn:uuid:{}", achievement_id);

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
                "id": achievement_id,
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
}

/// Parameterized version of oidc4vci_rs::verify_credential_request
#[async_trait]
pub trait VerifyCredentialRequest {
    async fn verify_credential_request<F>(&self,
                                       request: &CredentialRequest,
                                       token: &str,
                                       metadata: &Metadata,
                                       interface: &SSI,
                                       external_format_verifier: Option<F>,
                                       ) -> Result<String, oidc4vci_rs::OIDCError>
    where
        F: FnOnce(&str, &str) -> bool + Send + Copy;
}

/// oidc4vci_rs::verify_credential_request singleton for VerifyCredentialRequest
pub struct OIDC4VCIVerifyCredentialRequest {}

#[async_trait]
impl VerifyCredentialRequest for OIDC4VCIVerifyCredentialRequest {
    async fn verify_credential_request<F>(&self,
                                       request: &CredentialRequest,
                                       token: &str,
                                       metadata: &Metadata,
                                       interface: &SSI,
                                       external_format_verifier: Option<F>,
                                       ) -> Result<String, oidc4vci_rs::OIDCError>
    where
        F: FnOnce(&str, &str) -> bool + Send + Copy,
    {
        oidc4vci_rs::verify_credential_request(request,
                                               token,
                                               metadata,
                                               interface,
                                               external_format_verifier,
                                               ).await
    }
}

/// Error's with a default oidc4vci_rs::OIDCError reason and the unknown format
pub fn default_unknown_credential_handler(credential_format: &String,
                                          _issuer: String,
                                          _credential: ssi::vc::Credential,
                                          _did_resolver: &dyn ssi::did_resolve::DIDResolver,
                                          _verification_method: String,
                                          _interface: &SSI) -> Result<Value, crate::error::Error> {
    let mut err: oidc4vci_rs::OIDCError = Default::default();
    err.description = Some(format!("<credential endpoint, unknown format: {}>", credential_format));
    Err(From::from(err))
}

pub async fn post_credential_mult<F, G, H, I>(
    credential_requests: Vec<CredentialRequest>,
    token: &AuthorizationToken,
    metadata: &Metadata,
    config: &Config,
    interface: &SSI,
    credential_request_verifier: F,
    generate_credential_json: G,
    external_format_verifier: Option<H>,
    unknown_credential_handler: I,
) -> Vec<Result<Value, crate::error::Error>>
where
    F: VerifyCredentialRequest + Copy,
    G: FnOnce(String, String, VCDateTime, VCDateTime, String) -> Value + Copy,
    H: FnOnce(&str, &str) -> bool + Send + Copy,
    I: FnOnce(&String, String, ssi::vc::Credential, &dyn ssi::did_resolve::DIDResolver, String, &SSI) -> Result<Value, crate::error::Error> + Copy,
{
    let mut results = Vec::with_capacity(credential_requests.len());

    for credential_request in credential_requests {
        let result =
            post_credential(credential_request,
                            token,
                            metadata,
                            config,
                            interface,
                            credential_request_verifier,
                            generate_credential_json,
                            external_format_verifier,
                            unknown_credential_handler,
                            ).await;
        results.push(result);
    }

    results
}

// #[post("/credential", data = "<credential_request>")]
pub async fn post_credential<F, G, H, I>(
    credential_request: CredentialRequest,
    token: &AuthorizationToken,
    metadata: &Metadata,
    config: &Config,
    interface: &SSI,
    credential_request_verifier: F,
    generate_credential_json: G,
    external_format_verifier: Option<H>,
    unknown_credential_handler: I,
) -> Result<Value, crate::error::Error>
where
    F: VerifyCredentialRequest,
    G: FnOnce(String, String, VCDateTime, VCDateTime, String) -> Value,
    H: FnOnce(&str, &str) -> bool + Send + Copy,
    I: FnOnce(&String, String, ssi::vc::Credential, &dyn ssi::did_resolve::DIDResolver, String, &SSI) -> Result<Value, crate::error::Error> + Copy,
{
    println!("credential 1");

    let did = credential_request_verifier.verify_credential_request(
        &credential_request,
        &token.0,
        metadata,
        interface,
        external_format_verifier,
        // None::<oidc4vci_rs::ExternalFormatVerifier>,
    )
    .await?;

    println!("credential 2");

    let did_method = DID_METHODS.get(&config.did_method).unwrap();
    let issuer = did_method.generate(&Source::Key(&interface.jwk)).unwrap();

    let id = Uuid::new_v4().to_string();
    let id = format!("urn:uuid:{}", id);

    let iat = Utc::now();
    let iat = iat.duration_trunc(Duration::seconds(1)).unwrap();
    let iat = VCDateTime::from(iat);

    let exp = Utc::now() + Duration::days(1);
    let exp = exp.duration_trunc(Duration::seconds(1)).unwrap();
    let exp = VCDateTime::from(exp);

    println!("credential 3");

    let credential_json = generate_credential_json(id, issuer.clone(), iat, exp, did);
    let credential = serde_json::to_string(&credential_json)
        .unwrap();

    println!("credential 4");

    let mut credential = ssi::vc::Credential::from_json_unsigned(&credential).unwrap();

    let did_resolver = did_method.to_resolver();
    let verification_method =
        get_verification_methods_for_purpose(&issuer, did_resolver, ProofPurpose::AssertionMethod)
            .await
            .unwrap()
            .first()
            .unwrap()
            .to_owned();

    println!("credential 5");

    let format = credential_request.format.unwrap();

    use oidc4vci_rs::{CredentialFormat::*, MaybeUnknownCredentialFormat::*};

    let credential = match format {
        Known(JWT) => credential
            .generate_jwt(
                Some(&interface.jwk),
                &LinkedDataProofOptions {
                    proof_purpose: Some(ProofPurpose::AssertionMethod),
                    verification_method: Some(URI::String(verification_method)),
                    checks: None,
                    created: None,
                    ..LinkedDataProofOptions::default()
                },
                did_resolver,
            )
            .await
            .unwrap()
            .into(),

        Known(LDP) => {
            let proof = credential
                .generate_proof(
                    &interface.jwk,
                    &LinkedDataProofOptions {
                        proof_purpose: Some(ProofPurpose::AssertionMethod),
                        verification_method: Some(URI::String(verification_method)),
                        ..LinkedDataProofOptions::default()
                    },
                    did_resolver,
                    &mut ContextLoader::default(),
                )
                .await
                // .unwrap();
                // .expect("CredentialFormat::LDP: credential.generate_proof failed");
                .unwrap_or_else(|e| {
                    panic!(
                        "CredentialFormat::LDP: credential.generate_proof failed: {:?}",
                        e
                    )
                });
            credential.add_proof(proof);
            serde_json::to_value(&credential).unwrap()
        },

        Known(_) => unreachable!(),

        Unknown(ref credential_format) => {
            unknown_credential_handler(credential_format, issuer, credential, did_resolver, verification_method, interface)?
        },
    };

    println!("credential 6");
    Ok(serde_json::to_value(generate_credential_response(&format, credential)).unwrap())

}

