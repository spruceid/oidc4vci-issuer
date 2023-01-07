use crate::types::Config;
use chrono::{Duration, DurationRound, Utc};
use oidc4vci_rs::{IssuanceRequestParams, SSI};
use qrcode::{render::svg, QrCode};
use rand::{
    distributions::{Distribution, Uniform},
    thread_rng,
};
use rocket::{get, post, FromForm, State};
use rocket_dyn_templates::{context, Template};
use serde::Deserialize;
use serde_json::json;

#[derive(FromForm)]
pub struct IndexQueryParams {
    #[field(name = "pin")]
    pin: Option<bool>,

    #[field(name = "protocol")]
    protocol: Option<String>,

    #[field(name = "url")]
    url: Option<String>,
}

#[get("/?<query..>")]
pub fn index(query: IndexQueryParams, config: &State<Config>, interface: &State<SSI>) -> Template {
    let IndexQueryParams {
        pin, protocol, url, ..
    } = query;

    let dist = Uniform::from(0..999999);
    let user_pin_required = pin.unwrap_or(false);
    let pin = if user_pin_required {
        Some(format!("{:06}", dist.sample(&mut thread_rng())))
    } else {
        None
    };

    let exp = ssi::vc::VCDateTime::from(
        (Utc::now() + Duration::minutes(5))
            .duration_trunc(Duration::seconds(1))
            .unwrap(),
    );
    let pre_authz_code = oidc4vci_rs::generate_preauthz_code(
        serde_json::from_value(json!({
            "pin": pin,
            "credential_type": ["OpenBadgeCredential"],
            "exp": exp,
        }))
        .unwrap(),
        interface.inner(),
    )
    .unwrap();

    let data = oidc4vci_rs::generate_initiate_issuance_request(
        protocol.as_deref().unwrap_or("openid-initiate-issuance"),
        url.as_deref(),
        IssuanceRequestParams::with_user_pin(
            &config.issuer,
            "OpenBadgeCredential",
            &pre_authz_code,
            user_pin_required,
        ),
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
            pin: pin,
        },
    )
}

#[derive(Deserialize, FromForm)]
pub struct PreAuthQueryParams {
    #[field(name = "pin")]
    pub pin: Option<String>,

    #[field(name = "type")]
    pub type_: String,

    #[field(name = "user_id")]
    #[allow(dead_code)]
    pub user_id: String,
}

#[post("/issuer/preauth?<query..>")]
pub fn preauth(query: PreAuthQueryParams, interface: &State<SSI>) -> String {
    let PreAuthQueryParams { pin, type_, .. } = query;

    let exp = ssi::vc::VCDateTime::from(
        (Utc::now() + Duration::minutes(5))
            .duration_trunc(Duration::seconds(1))
            .unwrap(),
    );
    let pre_authz_code = oidc4vci_rs::generate_preauthz_code(
        serde_json::from_value(json!({
            "pin": pin,
            "credential_type": [type_],
            "exp": exp,
        }))
        .unwrap(),
        interface.inner(),
    )
    .unwrap();

    pre_authz_code
}
