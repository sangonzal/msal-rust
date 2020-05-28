#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use msal::AuthorizationUrl;
use msal::ClientApplication;
use msal::PublicClient;
use msal::TokenResponse;
use rocket::request::LenientForm;
use rocket::response::Redirect;
use serde::Deserialize;

const AUTHORITY: &'static str = "https://login.microsoftonline.com/sgonz.onmicrosoft.com";
const CLIENT_ID: &'static str = "a7aa6a47-d178-4d4d-be99-3eb11e33b475";
const SCOPES: &'static str = "openid";
const REDIRECT_URI: &'static str = "http://localhost:8000/redirect";

#[get("/")]
fn index() -> Redirect {
    let url = AuthorizationUrl::new(CLIENT_ID, REDIRECT_URI, &vec![SCOPES])
        .response_mode("form_post")
        .prompt("login")
        .build();
    println!("{}", &url);
    Redirect::to(url)
}

#[derive(FromForm)]
struct AuthorizationResponse {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[post(
    "/redirect",
    format = "application/x-www-form-urlencoded",
    data = "<auth_response>"
)]
fn redirect(auth_response: LenientForm<AuthorizationResponse>) -> String {
    if let Some(code) = &auth_response.code {
        let pca = PublicClient::new(CLIENT_ID, AUTHORITY);
        let auth_result: TokenResponse =
            pca.acquire_token_by_auth_code(&vec![SCOPES], &code, REDIRECT_URI);
        if let Some(error_description) = &auth_result.error_description {
            return auth_result.error_description.unwrap();
        } else {
            return format!(
                "AAD returned: \n
                Access token: {} \n
                Id token: {} \n",
                auth_result.access_token.unwrap(),
                auth_result.id_token.unwrap()
            );
        }
    } else {
        if let Some(error) = &auth_response.error {
            return format!(
                "AAD returned error {}: {}",
                error,
                auth_response.error_description.as_ref().unwrap()
            );
        } else {
            return format!("No auth code or error returned from AAD");
        }
    }
}

fn main() {
    rocket::ignite()
        .mount("/", routes![index, redirect])
        .launch();
}
