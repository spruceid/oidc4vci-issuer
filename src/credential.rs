use chrono::{Duration, Utc};
use oidc4vci_rs::{generate_credential_response, CredentialRequest, SSI};
use rocket::{post, serde::json::Json, State};
use serde_json::{json, Value};
use ssi::vc::{
    get_verification_methods_for_purpose, LinkedDataProofOptions, ProofPurpose, VCDateTime, URI,
};
use uuid::Uuid;

use crate::{authorization::AuthorizationToken, Metadata};

#[post("/credential", data = "<credential_request>")]
pub async fn post(
    credential_request: Json<CredentialRequest>,
    token: AuthorizationToken,
    metadata: &State<Metadata>,
    interface: &State<SSI>,
) -> Json<Value> {
    let credential_request = credential_request.into_inner();

    let did = oidc4vci_rs::verify_credential_request(
        &credential_request,
        &token.0,
        metadata.inner(),
        interface.inner(),
    )
    .await;

    let did_method = didkit::DID_METHODS.get("key").unwrap();
    let issuer = did_method
        .generate(&didkit::Source::Key(&interface.jwk))
        .unwrap();

    let id = Uuid::new_v4().to_string();
    let id = format!("urn:uuid:{}", id);

    let iat = VCDateTime::from(Utc::now());
    let exp = VCDateTime::from(Utc::now() + Duration::days(1));

    let credential = serde_json::to_string(&json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/jff-vc-edu-plugfest-1-context.json",
        ],
        "type": [
            "VerifiableCredential",
            "OpenBadgeCredential",
        ],
        "id": id,
        "issuanceDate": iat,
        "expirationDate": exp,
        "issuer": {
            "id": issuer,
            "image": "https://kayaelle.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
            "name": "Jobs for the Future (JFF)",
            "type": "Profile",
            "url": "https://www.jff.org/",
        },
        "credentialSubject": {
            "type": "AchievementSubject",
            "id": did,
            "achievement": {
                "criteria": {
                    "narrative": "The first cohort of the JFF Plugfest 1 in May/June of 2021 collaborated to push interoperability of VCs in education forward.",
                    "type": "Criteria"
                },
                "description": "This wallet can display this Open Badge 3.0",
                "image": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/plugfest-1-badge-image.png",
                "name": "Our Wallet Passed JFF Plugfest #1 2022",
                "type": "Achievement"
            },
        },
    })).unwrap();

    let mut credential = ssi::vc::Credential::from_json(&credential).unwrap();

    let did_resolver = did_method.to_resolver();
    let verification_method =
        get_verification_methods_for_purpose(&issuer, did_resolver, ProofPurpose::AssertionMethod)
            .await
            .unwrap()
            .first()
            .unwrap()
            .to_owned();

    let options = LinkedDataProofOptions {
        proof_purpose: Some(ProofPurpose::AssertionMethod),

        verification_method: Some(URI::String(verification_method)),
        ..LinkedDataProofOptions::default()
    };

    let credential = match &credential_request.format {
        oidc4vci_rs::CredentialFormat::JWT => credential
            .generate_jwt(Some(&interface.jwk), &options, did_resolver)
            .await
            .unwrap(),

        oidc4vci_rs::CredentialFormat::LDP => {
            let proof = credential
                .generate_proof(&interface.jwk, &options, did_resolver)
                .await
                .unwrap();
            credential.add_proof(proof);
            serde_json::to_string(&credential).unwrap()
        }

        _ => unreachable!(),
    };

    Json(
        serde_json::to_value(generate_credential_response(
            &credential_request.format,
            &serde_json::to_string(&credential).unwrap(),
        ))
        .unwrap(),
    )
}
