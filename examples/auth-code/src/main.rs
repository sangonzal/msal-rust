#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use msal::AuthorizationUrl;
use msal::ClientApplication;
use msal::PublicClient;
use msal::TokenResponse;
use rocket::response::Redirect;
use rocket_contrib::json::Json;
use serde::Deserialize;

const AUTHORITY: &'static str = "https://login.microsoftonline.com/sgonz.onmicrosoft.com";
const CLIENT_ID: &'static str = "a7aa6a47-d178-4d4d-be99-3eb11e33b475";
const SCOPES: &'static str = "openid";
const REDIRECT_URI: &'static str = "http://localhost:8000/redirect";

#[get("/")]
fn index() -> Redirect {
    let url = AuthorizationUrl::new(CLIENT_ID, REDIRECT_URI, &vec![SCOPES])
        .response_mode("form_post")
        .build();
    println!("{}", &url);
    Redirect::to(url)
}

#[derive(Deserialize)]
struct AuthorizationResponse {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[post("/redirect", data = "<auth_response>")]
fn redirect(auth_response: Json<AuthorizationResponse>) -> String {
    println!("{}", "Redirected back");
    if let Some(code) = &auth_response.code {
        let pca = PublicClient::new(CLIENT_ID, AUTHORITY);
        let auth_result: TokenResponse =
            pca.acquire_token_by_auth_code(&vec![SCOPES], &code, REDIRECT_URI);
        let id_token = auth_result.id_token.unwrap();
        id_token
    } else {
        if let Some(error) = &auth_response.error {
            format!(
                "AAD returned error {}: {}",
                error,
                auth_response.error_description.as_ref().unwrap()
            )
        } else {
            format!("No auth code or error returned from AAD")
        }
    }
}

fn main() {
    rocket::ignite().mount("/", routes![index]).launch();
}
