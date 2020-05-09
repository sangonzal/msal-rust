use msal::Authority;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{thread, time};
use url::form_urlencoded;

struct PublicClient<'a> {
    pub client_id: &'a str,
    authority: Authority,
}

struct AuthorizationCodeRequest {}

struct DeviceCodeRequest {}

const CLIENT_ID: &'static str = "client_id";
const SCOPES: &'static str = "scope";
const CODE: &'static str = "auth_code";
const REDIRECT_URI: &'static str = "redirect_uri";
const GRANT_TYPE: &'static str = "grant_type";
const DEVICE_CODE_GRANT: &'static str = "device_code";
const DEVICE_CODE: &'static str = "device_code";

trait ClientApplication {
    fn client_id(&self) -> &str;

    fn authority(&self) -> String;

    fn acquire_token_by_auth_code(
        &self,
        scopes: Vec<&str>,
        auth_code: &str,
        redirect_uri: &str,
    ) -> String {
        let scopes = &*scopes.join(" ");

        let mut parameters = HashMap::new();

        parameters.insert(CLIENT_ID, self.client_id());
        parameters.insert(SCOPES, scopes);
        parameters.insert(CODE, auth_code);
        parameters.insert(REDIRECT_URI, redirect_uri);
        parameters.insert(GRANT_TYPE, "authorization_code");

        let encoded_query = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(parameters)
            .finish();

        encoded_query
    }
}

#[derive(Clone, Deserialize)]
struct TokenResponse {
    expires_in: Option<u64>,
    ext_expires_in: Option<u64>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,

    // Error
    error: Option<String>,
    error_description: Option<String>,
    error_codes: Option<Vec<usize>>,
    timestamp: Option<String>,
    trace_id: Option<String>,
    correlation_id: Option<String>,
}

#[derive(Clone, Deserialize)]
struct DeviceCodeResponse {
    user_code: String,
    device_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
    message: String,
}

impl<'a> PublicClient<'a> {
    pub fn new(client_id: &'a str, authority: &'a str) -> PublicClient<'a> {
        let authority = Authority::new(authority);
        return PublicClient {
            client_id,
            authority,
        };
    }

    pub fn acquire_token_by_device_flow(
        &self,
        scopes: Vec<&str>,
        callback: fn(device_code_response: DeviceCodeResponse),
    ) -> Result<TokenResponse, Box<dyn Error>> {
        let scopes: &str = &*scopes.join(" ");

        let mut parameters = HashMap::new();
        parameters.insert(CLIENT_ID, self.client_id());
        parameters.insert(SCOPES, scopes);

        let request_body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(parameters)
            .finish();

        let device_code_response: DeviceCodeResponse =
            msal::http_post(&self.authority.device_code_endpoint, request_body)
                .unwrap()
                .json()
                .unwrap();
        callback(device_code_response.clone());

        let mut token_request_parameters: HashMap<&'static str, &str> = HashMap::new();
        token_request_parameters.insert(CLIENT_ID, self.client_id());
        token_request_parameters.insert(SCOPES, scopes);
        token_request_parameters.insert(GRANT_TYPE, DEVICE_CODE_GRANT);
        token_request_parameters.insert(DEVICE_CODE, &device_code_response.device_code);

        let device_code_body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(token_request_parameters)
            .finish();

        let device_code_expiration = device_code_response.expires_in
            + SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

        loop {
            if device_code_expiration
                < SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            {
                return Err("Device code expired")?;
            }

            // TODO add cancellation

            let response =
                msal::http_post(&self.authority.token_endpoint, device_code_body.clone()).unwrap();

            let json_response: TokenResponse = response.json().unwrap();

            match json_response.error.as_ref().map(String::as_str) {
                Some("authorization_pending") => println!("{}", json_response.error.unwrap()),
                None => return Ok(json_response),
                _ => return Err(json_response.error_description.unwrap())?,
            }

            thread::sleep(time::Duration::from_secs(device_code_response.interval))
        }
    }
}

impl ClientApplication for PublicClient<'_> {
    fn client_id(&self) -> &str {
        return self.client_id;
    }

    fn authority(&self) -> String {
        return self.authority.authority_url.clone();
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let authority = "https://login.microsoftonline.com/sgonz.onmicrosoft.com";
    let client_id = "6c04f413-f6e7-4690-b372-dbdd083e7e5a";

    let scopes: Vec<&str> = vec!["user.read"];
    let auth_code = "auth_code";
    let redirect_uri = "https://localhost:8080";

    let pca = PublicClient::new(client_id, authority);

    //let resp = pca.acquire_token_by_auth_code(scopes, auth_code, redirect_uri);

    let resp =
        pca.acquire_token_by_device_flow(scopes, |device_code_response: DeviceCodeResponse| {
            println!("{}", device_code_response.message);
        });

    println!("{}", &resp?.access_token.unwrap());

    Ok(())
}
