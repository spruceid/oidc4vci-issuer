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
                {
                    "id": "@id",
                    "type": "@type",
                    "xsd": "https://www.w3.org/2001/XMLSchema#",
                    "OpenBadgeCredential": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#OpenBadgeCredential"
                    },
                    "Achievement": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Achievement",
                        "@context": {
                            "achievementType": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#achievementType",
                                "@type": "xsd:string"
                            },
                            "alignment": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#alignment",
                                "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Alignment",
                                "@container": "@set"
                            },
                            "creator": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Profile"
                            },
                            "creditsAvailable": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#creditsAvailable",
                                "@type": "xsd:float"
                            },
                            "criteria": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Criteria",
                                "@type": "@id"
                            },
                            "fieldOfStudy": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#fieldOfStudy",
                                "@type": "xsd:string"
                            },
                            "humanCode": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#humanCode",
                                "@type": "xsd:string"
                            },
                            "otherIdentifier": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#otherIdentifier",
                                "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#IdentifierEntry",
                                "@container": "@set"
                            },
                            "related": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#related",
                                "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Related",
                                "@container": "@set"
                            },
                            "resultDescription": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#resultDescription",
                                "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#ResultDescription",
                                "@container": "@set"
                            },
                            "specialization": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#specialization",
                                "@type": "xsd:string"
                            },
                            "tag": {
                                "@id": "https://schema.org/keywords",
                                "@type": "xsd:string",
                                "@container": "@set"
                            },
                            "version": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#version",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "AchievementCredential": {
                        "@id": "OpenBadgeCredential"
                    },
                    "AchievementSubject": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#AchievementSubject",
                        "@context": {
                            "achievement": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Achievement"
                            },
                            "activityEndDate": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#activityEndDate",
                                "@type": "xsd:date"
                            },
                            "activityStartDate": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#activityStartDate",
                                "@type": "xsd:date"
                            },
                            "creditsEarned": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#creditsEarned",
                                "@type": "xsd:float"
                            },
                            "identifier": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identifier",
                                "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#IdentityObject",
                                "@container": "@set"
                            },
                            "licenseNumber": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#licenseNumber",
                                "@type": "xsd:string"
                            },
                            "result": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#result",
                                "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Result",
                                "@container": "@set"
                            },
                            "role": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#role",
                                "@type": "xsd:string"
                            },
                            "source": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#source",
                                "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Profile"
                            },
                            "term": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#term",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "Address": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Address",
                        "@context": {
                            "addressCountry": {
                                "@id": "https://schema.org/addressCountry",
                                "@type": "xsd:string"
                            },
                            "addressCountryCode": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#CountryCode",
                                "@type": "xsd:string"
                            },
                            "addressLocality": {
                                "@id": "https://schema.org/addressLocality",
                                "@type": "xsd:string"
                            },
                            "addressRegion": {
                                "@id": "https://schema.org/addressRegion",
                                "@type": "xsd:string"
                            },
                            "geo": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#GeoCoordinates"
                            },
                            "postOfficeBoxNumber": {
                                "@id": "https://schema.org/postOfficeBoxNumber",
                                "@type": "xsd:string"
                            },
                            "postalCode": {
                                "@id": "https://schema.org/postalCode",
                                "@type": "xsd:string"
                            },
                            "streetAddress": {
                                "@id": "https://schema.org/streetAddress",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "Alignment": {
                        "@id": "https://schema.org/Alignment",
                        "@context": {
                            "targetCode": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#targetCode",
                                "@type": "xsd:string"
                            },
                            "targetDescription": {
                                "@id": "https://schema.org/targetDescription",
                                "@type": "xsd:string"
                            },
                            "targetFramework": {
                                "@id": "https://schema.org/targetFramework",
                                "@type": "xsd:string"
                            },
                            "targetName": {
                                "@id": "https://schema.org/targetName",
                                "@type": "xsd:string"
                            },
                            "targetType": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#targetType",
                                "@type": "xsd:string"
                            },
                            "targetUrl": {
                                "@id": "https://schema.org/targetUrl",
                                "@type": "xsd:anyURI"
                            }
                        }
                    },
                    "Criteria": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Criteria"
                    },
                    "EndorsementCredential": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#EndorsementCredential"
                    },
                    "EndorsementSubject": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#EndorsementSubject",
                        "@context": {
                            "endorsementComment": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#endorsementComment",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "Evidence": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Evidence",
                        "@context": {
                            "audience": {
                                "@id": "https://schema.org/audience",
                                "@type": "xsd:string"
                            },
                            "genre": {
                                "@id": "https://schema.org/genre",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "GeoCoordinates": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#GeoCoordinates",
                        "@context": {
                            "latitude": {
                                "@id": "https://schema.org/latitude",
                                "@type": "xsd:string"
                            },
                            "longitude": {
                                "@id": "https://schema.org/longitude",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "IdentifierEntry": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#IdentifierEntry",
                        "@context": {
                            "identifier": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identifier",
                                "@type": "xsd:string"
                            },
                            "identifierType": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identifierType",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "IdentityObject": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#IdentityObject",
                        "@context": {
                            "hashed": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#hashed",
                                "@type": "xsd:boolean"
                            },
                            "identityHash": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identityHash",
                                "@type": "xsd:string"
                            },
                            "identityType": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identityType",
                                "@type": "xsd:string"
                            },
                            "salt": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#salt",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "Image": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Image",
                        "@context": {
                            "caption": {
                                "@id": "https://schema.org/caption",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "Profile": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Profile",
                        "@context": {
                            "additionalName": {
                                "@id": "https://schema.org/additionalName",
                                "@type": "xsd:string"
                            },
                            "address": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Address"
                            },
                            "dateOfBirth": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#dateOfBirth",
                                "@type": "xsd:date"
                            },
                            "email": {
                                "@id": "https://schema.org/email",
                                "@type": "xsd:string"
                            },
                            "familyName": {
                                "@id": "https://schema.org/familyName",
                                "@type": "xsd:string"
                            },
                            "familyNamePrefix": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#familyNamePrefix",
                                "@type": "xsd:string"
                            },
                            "givenName": {
                                "@id": "https://schema.org/givenName",
                                "@type": "xsd:string"
                            },
                            "honorificPrefix": {
                                "@id": "https://schema.org/honorificPrefix",
                                "@type": "xsd:string"
                            },
                            "honorificSuffix": {
                                "@id": "https://schema.org/honorificSuffix",
                                "@type": "xsd:string"
                            },
                            "otherIdentifier": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#otherIdentifier",
                                "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#IdentifierEntry",
                                "@container": "@set"
                            },
                            "parentOrg": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#parentOrg",
                                "@type": "xsd:string"
                            },
                            "patronymicName": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#patronymicName",
                                "@type": "xsd:string"
                            },
                            "phone": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#PhoneNumber",
                                "@type": "xsd:string"
                            },
                            "official": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#official",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "Related": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Related",
                        "@context": {
                            "version": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#version",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "Result": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Result",
                        "@context": {
                            "achievedLevel": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#achievedLevel",
                                "@type": "xsd:anyURI"
                            },
                            "resultDescription": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#resultDescription",
                                "@type": "xsd:anyURI"
                            },
                            "status": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#status",
                                "@type": "xsd:string"
                            },
                            "value": {
                                "@id": "https://schema.org/value",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "ResultDescription": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#ResultDescription",
                        "@context": {
                            "allowedValue": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#allowedValue",
                                "@type": "xsd:string",
                                "@container": "@set"
                            },
                            "requiredLevel": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#requiredLevel",
                                "@type": "xsd:anyURI"
                            },
                            "requiredValue": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#requiredValue",
                                "@type": "xsd:string"
                            },
                            "resultType": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#resultType",
                                "@type": "xsd:string"
                            },
                            "rubricCriterionLevel": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#rubricCriterionLevel",
                                "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#RubricCriterionLevel",
                                "@container": "@set"
                            },
                            "valueMax": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#valueMax",
                                "@type": "xsd:string"
                            },
                            "valueMin": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#valueMin",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "RubricCriterionLevel": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#RubricCriterionLevel",
                        "@context": {
                            "level": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#level",
                                "@type": "xsd:string"
                            },
                            "points": {
                                "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#points",
                                "@type": "xsd:string"
                            }
                        }
                    },
                    "alignment": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#alignment",
                        "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Alignment",
                        "@container": "@set"
                    },
                    "description": {
                        "@id": "https://schema.org/description",
                        "@type": "xsd:string"
                    },
                    "endorsement": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#endorsement",
                        "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#EndorsementCredential",
                        "@container": "@set"
                    },
                    "image": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#image",
                        "@type": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Image"
                    },
                    "name": {
                        "@id": "https://schema.org/name",
                        "@type": "xsd:string"
                    },
                    "narrative": {
                        "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#narrative",
                        "@type": "xsd:string"
                    },
                    "url": {
                        "@id": "https://schema.org/url",
                        "@type": "xsd:anyURI"
                    }
                }
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
