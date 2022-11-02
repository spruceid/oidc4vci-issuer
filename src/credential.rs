use chrono::{Duration, Utc};
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

pub async fn post_credential_mult<F>(
    credential_requests: Vec<CredentialRequest>,
    token: &AuthorizationToken,
    metadata: &Metadata,
    config: &Config,
    interface: &SSI,
    f: &F,
) -> Vec<Result<Value, crate::error::Error>>
where
    F: FnOnce(String, String, VCDateTime, VCDateTime, String) -> Value + Copy,
{
    let mut results = Vec::with_capacity(credential_requests.len());

    for credential_request in credential_requests {
        let result =
            post_credential(credential_request, token, metadata, config, interface, f).await;
        results.push(result);
    }

    results
}

// #[post("/credential", data = "<credential_request>")]
pub async fn post_credential<F>(
    credential_request: CredentialRequest,
    token: &AuthorizationToken,
    metadata: &Metadata,
    config: &Config,
    interface: &SSI,
    f: &F,
) -> Result<Value, crate::error::Error>
where
    F: FnOnce(String, String, VCDateTime, VCDateTime, String) -> Value + Copy,
{
    let did =
        oidc4vci_rs::verify_credential_request(&credential_request, &token.0, metadata, interface)
            .await?;

    let did_method = DID_METHODS.get(&config.did_method).unwrap();
    let issuer = did_method.generate(&Source::Key(&interface.jwk)).unwrap();

    let id = Uuid::new_v4().to_string();
    let id = format!("urn:uuid:{}", id);

    let iat = VCDateTime::from(Utc::now());
    let exp = VCDateTime::from(Utc::now() + Duration::days(1));

    let credential_json = f(id, issuer.clone(), iat, exp, did);
    let credential = serde_json::to_string(&credential_json).unwrap();

    let mut credential = ssi::vc::Credential::from_json_unsigned(&credential).unwrap();

    let did_resolver = did_method.to_resolver();
    let verification_method =
        get_verification_methods_for_purpose(&issuer, did_resolver, ProofPurpose::AssertionMethod)
            .await
            .unwrap()
            .first()
            .unwrap()
            .to_owned();

    let format = credential_request.format.unwrap();
    let credential = match format {
        oidc4vci_rs::CredentialFormat::JWT => credential
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

        oidc4vci_rs::CredentialFormat::LDP => {
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
