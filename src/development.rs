use chrono::{Duration, Utc};
use oidc4vci_rs::IssuanceRequestParams;
use qrcode::{render::svg, QrCode};
use rocket::{get, post, FromForm, State};
use rocket_dyn_templates::{context, Template};
use serde_json::json;

#[get("/")]
pub fn index(config: &State<crate::Config>, interface: &State<oidc4vci_rs::SSI>) -> Template {
    let pre_authz_code = oidc4vci_rs::generate_preauthz_code(
        serde_json::from_value(json!({
            "credential_type": ["OpenBadgeCredential"],
            "exp": ssi::vc::VCDateTime::from(Utc::now() + Duration::minutes(5)),
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

#[derive(FromForm)]
pub struct PreAuthQueryParams {
    #[field(name = "pin")]
    pin: Option<String>,

    #[field(name = "type")]
    type_: String,

    #[field(name = "user_id")]
    user_id: String,
}

#[post("/issuer/preauth?<query..>")]
pub fn preauth(query: PreAuthQueryParams, interface: &State<oidc4vci_rs::SSI>) -> String {
    let PreAuthQueryParams { pin, type_, .. } = query;

    let pre_authz_code = oidc4vci_rs::generate_preauthz_code(
        serde_json::from_value(json!({
            "pin": pin,
            "credential_type": [type_],
            "exp": ssi::vc::VCDateTime::from(Utc::now() + Duration::minutes(5)),
        }))
        .unwrap(),
        interface.inner(),
    )
    .unwrap();

    pre_authz_code
}
