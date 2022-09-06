use chrono::Utc;
use oidc4vci_rs::{CredentialFormat, IssuanceRequestParams};
use qrcode::{render::svg, QrCode};
use rocket::{get, launch, routes, State};
use rocket_dyn_templates::{context, Template};
use serde_json::json;

mod authorization;
mod configuration;
mod credential;
mod token;

pub struct Config {
    issuer: String,
}

pub struct Metadata {
    audience: String,
    credential_types: Vec<String>,
    formats: Vec<CredentialFormat>,
}

impl oidc4vci_rs::Metadata for Metadata {
    fn get_audience(&self) -> &str {
        &self.audience
    }

    fn get_credential_types(&self) -> std::slice::Iter<'_, String> {
        self.credential_types.iter()
    }

    fn get_allowed_formats(&self, _: &str) -> std::slice::Iter<'_, oidc4vci_rs::CredentialFormat> {
        self.formats.iter()
    }
}

#[get("/")]
fn index(config: &State<Config>, interface: &State<oidc4vci_rs::SSI>) -> Template {
    let pre_authz_code = oidc4vci_rs::generate_preauthz_code(
        serde_json::from_value(json!({
            "credential_type": [],
            "exp": ssi::vc::VCDateTime::from(Utc::now()),
        }))
        .unwrap(),
        interface.inner(),
    )
    .unwrap();

    let data = oidc4vci_rs::generate_initiate_issuance_request(
        "openid-initiate-issuance",
        None,
        IssuanceRequestParams::new(&config.issuer, "OpenBadgeCredential", &pre_authz_code),
    );

    let code = QrCode::new(&data).unwrap();
    let image = code
        .render()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();

    Template::render(
        "index",
        context! {
            url: data,
            image: image,
        },
    )
}

#[launch]
fn rocket() -> _ {
    dotenv::dotenv().ok();

    let issuer = std::env::var("ISSUER").expect("Failed to load ISSUER");
    let jwk = std::env::var("JWK").expect("Failed to load JWK");

    let interface = oidc4vci_rs::SSI::new(
        serde_json::from_str(&jwk).expect("Failed to parse JWK"),
        ssi::jwk::Algorithm::EdDSA,
    );

    let metadata = Metadata {
        audience: issuer.to_owned(),
        credential_types: vec!["OpenBadgeCredential".into()],
        formats: vec![CredentialFormat::JWT],
    };

    let config = Config { issuer };

    rocket::build()
        .manage(interface)
        .manage(metadata)
        .manage(config)
        .mount(
            "/",
            routes![
                index,
                credential::post,
                token::post,
                configuration::openid,
                configuration::jwks,
            ],
        )
        .attach(Template::fairing())
}
