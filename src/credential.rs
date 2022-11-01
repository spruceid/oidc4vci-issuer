use chrono::{Duration, Utc};
use oidc4vci_rs::{generate_credential_response, CredentialRequest, SSI};
use rocket::{serde::json::Json, State};
use serde_json::Value;
use ssi::{
    did::Source,
    jsonld::ContextLoader,
    vc::{
        get_verification_methods_for_purpose, LinkedDataProofOptions, ProofPurpose, VCDateTime, URI,
    },
};
use uuid::Uuid;

use crate::{authorization::AuthorizationToken, types::{DID_METHODS, Config, Metadata}};

// #[post("/credential", data = "<credential_request>")]
pub async fn post_credential<F>(
    credential_request: Json<CredentialRequest>,
    token: AuthorizationToken,
    metadata: &State<Metadata>,
    config: &State<Config>,
    interface: &State<SSI>,
    f: F,
) -> Result<Json<Value>, crate::error::Error>
where
    F: FnOnce(String, String, VCDateTime, VCDateTime, String) -> Value,
{
    let credential_request = credential_request.into_inner();

    let did = oidc4vci_rs::verify_credential_request(
        &credential_request,
        &token.0,
        metadata.inner(),
        interface.inner(),
    )
    .await?;

    let did_method = DID_METHODS.get(&config.did_method).unwrap();
    let issuer = did_method.generate(&Source::Key(&interface.jwk)).unwrap();

    let id = Uuid::new_v4().to_string();
    let id = format!("urn:uuid:{}", id);

    let iat = VCDateTime::from(Utc::now());
    let exp = VCDateTime::from(Utc::now() + Duration::days(1));

    let credential_json = f(id, issuer.clone(), iat, exp, did);
    let credential = serde_json::to_string(&credential_json)
        .unwrap();

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
                .unwrap_or_else(|e| panic!("CredentialFormat::LDP: credential.generate_proof failed: {:?}", e));
            credential.add_proof(proof);
            serde_json::to_value(&credential).unwrap()
        }

        _ => unreachable!(),
    };

    Ok(Json(
        serde_json::to_value(generate_credential_response(&format, credential)).unwrap(),
    ))
}
