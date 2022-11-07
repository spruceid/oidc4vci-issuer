use async_trait::async_trait;
use chrono::{Duration, DurationRound, Utc};
use oidc4vci_rs::{generate_credential_response, CredentialRequest, ExternalFormatVerifier, SSI};
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

#[async_trait]
pub trait VerifyCredentialRequest {
    async fn verify_credential_request<F>(
        &self,
        request: &CredentialRequest,
        token: &str,
        metadata: &Metadata,
        interface: &SSI,
        external_format_verifier: Option<&F>,
    ) -> Result<String, oidc4vci_rs::OIDCError>
    where
        F: ExternalFormatVerifier + Sync;
}

#[derive(Clone, Debug)]
pub struct DefaultRequestVerifier;

#[async_trait]
impl VerifyCredentialRequest for DefaultRequestVerifier {
    async fn verify_credential_request<F>(
        &self,
        request: &CredentialRequest,
        token: &str,
        metadata: &Metadata,
        interface: &SSI,
        external_format_verifier: Option<&F>,
    ) -> Result<String, oidc4vci_rs::OIDCError>
    where
        F: ExternalFormatVerifier + Sync,
    {
        oidc4vci_rs::verify_credential_request(
            request,
            token,
            metadata,
            interface,
            external_format_verifier,
        )
        .await
    }
}

#[async_trait]
pub trait CredentialHandler {
    async fn handle(
        &mut self,
        credential_request: CredentialRequest,
        token: &AuthorizationToken,
        metadata: &Metadata,
        config: &Config,
        interface: &SSI,
        did: &str,
    ) -> Result<Value, crate::error::Error>;
}

#[derive(Clone, Debug)]
pub struct DefaultCredentialHandler;

#[async_trait]
impl CredentialHandler for DefaultCredentialHandler {
    async fn handle(
        &mut self,
        credential_request: CredentialRequest,
        _token: &AuthorizationToken,
        _metadata: &Metadata,
        config: &Config,
        interface: &SSI,
        did: &str,
    ) -> Result<Value, crate::error::Error> {
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

        let achievement_id = Uuid::new_v4().to_string();
        let achievement_id = format!("urn:uuid:{}", achievement_id);

        let credential_json = serde_json::json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://purl.imsglobal.org/spec/ob/v3p0/context.json",
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
                "image": {
                  "id": "https://w3c-ccg.github.io/vc-ed/plugfest-2-2022/images/JFF-VC-EDU-PLUGFEST2-badge-image.png",
                  "type": "Image"
                }
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
        });

        let credential = serde_json::to_string(&credential_json).unwrap();

        let mut credential = ssi::vc::Credential::from_json_unsigned(&credential).unwrap();

        let did_resolver = did_method.to_resolver();
        let verification_method = get_verification_methods_for_purpose(
            &issuer,
            did_resolver,
            ProofPurpose::AssertionMethod,
        )
        .await
        .unwrap()
        .first()
        .unwrap()
        .to_owned();

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
            }

            _ => unreachable!(),
        };

        Ok(serde_json::to_value(generate_credential_response(&format, credential)).unwrap())
    }
}

pub async fn post_credential_mult<F, G, H>(
    credential_requests: Vec<CredentialRequest>,
    token: &AuthorizationToken,
    metadata: &Metadata,
    config: &Config,
    interface: &SSI,
    credential_request_verifier: &F,
    external_format_verifier: Option<&G>,
    credential_handler: &mut H,
) -> Vec<Result<Value, crate::error::Error>>
where
    F: VerifyCredentialRequest,
    G: ExternalFormatVerifier + Sync,
    H: CredentialHandler,
{
    let mut results = Vec::with_capacity(credential_requests.len());

    for credential_request in credential_requests {
        let result = post_credential(
            credential_request,
            token,
            metadata,
            config,
            interface,
            credential_request_verifier,
            external_format_verifier,
            credential_handler,
        )
        .await;
        results.push(result);
    }

    results
}

pub async fn post_credential<F, G, H>(
    credential_request: CredentialRequest,
    token: &AuthorizationToken,
    metadata: &Metadata,
    config: &Config,
    interface: &SSI,
    credential_request_verifier: &F,
    external_format_verifier: Option<&G>,
    credential_handler: &mut H,
) -> Result<Value, crate::error::Error>
where
    F: VerifyCredentialRequest,
    G: ExternalFormatVerifier + Sync,
    H: CredentialHandler,
{
    let did = credential_request_verifier
        .verify_credential_request(
            &credential_request,
            &token.0,
            metadata,
            interface,
            external_format_verifier,
        )
        .await?;

    credential_handler
        .handle(credential_request, token, metadata, config, interface, &did)
        .await
}
