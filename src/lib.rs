use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::cell::Ref;
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{thread, time};
use url::form_urlencoded;
use uuid::Uuid;

const CLIENT_ID: &'static str = "client_id";
const SCOPES: &'static str = "scope";
const CODE: &'static str = "code";
const REDIRECT_URI: &'static str = "redirect_uri";
const GRANT_TYPE: &'static str = "grant_type";
const DEVICE_CODE_GRANT: &'static str = "device_code";
const REFRESH_TOKEN_GRANT: &'static str = "refresh_token";
const AUTHORIZATION_CODE_GRANT: &'static str = "authorization_code";
const CLIENT_CREDENTIALS_GRANT: &'static str = "client_credentials";
const JWT_BEARER_GRANT_TYPE: &'static str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const CLIENT_ASSERTION_GRANT_TYPE: &'static str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ASSERTION_TYPE: &'static str = "client_assertion_type";
const ASSERTION: &'static str = "client_assertion";
const DEVICE_CODE: &'static str = "device_code";
const REFRESH_TOKEN: &'static str = "refresh_token";
const CLIENT_SECRET: &'static str = "client_secret";
const RESPONSE_MODE: &'static str = "response_mode";
const RESPONSE_TYPE: &'static str = "response_type";
const CODE_CHALLENGE: &'static str = "code_challenge";
const CODE_CHALLENGE_METHOD: &'static str = "code_challenge_method";
const STATE: &'static str = "state";
const PROMPT: &'static str = "prompt";
const LOGIN_HINT: &'static str = "login_hint";
const CLAIMS: &'static str = "claims";
const NONCE: &'static str = "nonce";
const TENANT_DISCOVERY_ENDPOINT: &'static str = "/v2.0/.well-known/openid-configuration";
const COMMON_AUTHORITY: &'static str = "https://login.microsoftonline.com/common";

pub struct PublicClient<'a> {
    pub client_id: &'a str,
    authority: Authority,
}

pub struct ConfidentialClient<'a> {
    pub client_id: &'a str,
    authority: Authority,
    credential: ClientCredential<'a>,
}

pub struct Certificate {
    encoding_key: EncodingKey,
    thumbprint: String
}

pub struct ClientCredential<'a> {
    assertion: RefCell<Option<Assertion>>,
    client_secret: Option<&'a str>,
    certificate: Option<Certificate>,
}

struct Assertion {
    assertion: String,
    expiration_time: u64,
}

impl<'a> ClientCredential<'a> {
    pub fn from_secret(client_secret: &'a str) -> Self {
        return ClientCredential {
            assertion: RefCell::new(None),
            client_secret: Some(client_secret),
            certificate: None,
        };
    }
    pub fn from_certificate(private_key: &[u8], thumbprint: String) -> Self {
        let certificate: Certificate = Certificate {
           encoding_key : jsonwebtoken::EncodingKey::from_rsa_pem(private_key).unwrap(),
           thumbprint
        };

        return ClientCredential {
            assertion: RefCell::new(None),
            client_secret: None,
            certificate: Some(certificate),
        };
    }

    fn get_assertion(&self, audience: &str, issuer: &str) -> Ref<'_, String> {
        if let Some(assertion) = &*self.assertion.borrow() {
            if assertion.expiration_time
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            {
                return Ref::map(self.assertion.borrow(), |value| {
                    &value.as_ref().expect("set above").assertion
                });
            } else {
                self.assertion.replace(Some(
                    self.create_assertion_from_certificate(audience, issuer),
                ));
                return Ref::map(self.assertion.borrow(), |value| {
                    &value.as_ref().expect("set above").assertion
                });
            }
        } else {
            panic!("No assertion set on application");
        }
    }

    fn create_assertion_from_certificate(&self, audience: &str, issuer: &str) -> Assertion {

        let mut header = Header::default();
        //TODO header.x5t = Some();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = AssertionClaims {
            aud: audience.to_string(),
            sub: issuer.to_string(),
            iss: issuer.to_string(),
            exp: 600 + now,
            iat: now,
            jti: Uuid::new_v4().to_string(),
        };

        let encoding_key = &self
            .certificate
            .as_ref()
            .unwrap()
            .encoding_key;

        return Assertion {
            assertion: jsonwebtoken::encode(&header, &claims, encoding_key).unwrap(),
            expiration_time: now,
        };
    }
}

impl<'a> ConfidentialClient<'a> {
    pub fn new(client_id: &'a str, authority: &'a str, credential: ClientCredential<'a>) -> Self {
        let authority = Authority::new(authority);

        return ConfidentialClient {
            client_id,
            authority,
            credential,
        };
    }

    pub fn acquire_token_for_client(&self, scopes: &Vec<&str>) -> TokenResponse {
        let scopes = &*scopes.join(" ");

        let mut parameters = HashMap::new();

        let assertion;
        if let Some(client_secret) = self.credential.client_secret {
            parameters.insert(CLIENT_SECRET, client_secret);
        } else {
            assertion = self
                .credential
                .get_assertion(&self.authority.token_endpoint, &self.client_id);
                
            parameters.insert(ASSERTION, &assertion);
            parameters.insert(ASSERTION_TYPE, CLIENT_ASSERTION_GRANT_TYPE);
        };

        parameters.insert(CLIENT_ID, &self.client_id());
        parameters.insert(SCOPES, scopes);
        parameters.insert(GRANT_TYPE, CLIENT_CREDENTIALS_GRANT);

        let token_request_body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(parameters)
            .finish();

        let response: TokenResponse =
            http_post(&self.authority().token_endpoint, token_request_body)
                .unwrap()
                .json()
                .unwrap();
        response
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AssertionClaims {
    aud: String,
    sub: String,
    iss: String,
    jti: String,
    iat: u64,
    exp: u64,
}

pub trait ClientApplication {
    fn client_id(&self) -> &str;

    fn authority(&self) -> &Authority;

    fn acquire_token_by_refresh_token(
        &self,
        scopes: &Vec<&str>,
        refresh_token: &str,
    ) -> TokenResponse {
        let scopes = &*scopes.join(" ");

        let mut parameters = HashMap::new();

        parameters.insert(CLIENT_ID, self.client_id());
        parameters.insert(SCOPES, scopes);
        parameters.insert(REFRESH_TOKEN, refresh_token);
        parameters.insert(GRANT_TYPE, REFRESH_TOKEN_GRANT);

        let token_request_body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(parameters)
            .finish();

        let response: TokenResponse =
            http_post(&self.authority().token_endpoint, token_request_body)
                .unwrap()
                .json()
                .unwrap();
        response
    }

    fn acquire_token_by_auth_code(
        &self,
        scopes: &Vec<&str>,
        auth_code: &str,
        redirect_uri: &str,
    ) -> TokenResponse {
        let scopes = &*scopes.join(" ");

        let mut parameters = HashMap::new();

        parameters.insert(CLIENT_ID, self.client_id());
        parameters.insert(SCOPES, scopes);
        parameters.insert(CODE, auth_code);
        parameters.insert(REDIRECT_URI, redirect_uri);
        parameters.insert(GRANT_TYPE, AUTHORIZATION_CODE_GRANT);

        let token_request_body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(parameters)
            .finish();

        let response: TokenResponse =
            http_post(&self.authority().token_endpoint, token_request_body)
                .unwrap()
                .json()
                .unwrap();
        response
    }
}

pub struct AuthorizationUrl<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a Vec<&'a str>,
    pub authority: Option<&'a str>,
    pub response_mode: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    pub state: Option<&'a str>,
    pub prompt: Option<&'a str>,
    pub login_hint: Option<&'a str>,
    pub claims: Option<&'a str>,
    pub nonce: Option<&'a str>,
}

impl<'a> AuthorizationUrl<'a> {
    pub fn new(
        client_id: &'a str,
        redirect_uri: &'a str,
        scopes: &'a Vec<&str>,
    ) -> AuthorizationUrl<'a> {
        AuthorizationUrl {
            client_id,
            redirect_uri,
            scopes,
            authority: None,
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            state: None,
            prompt: None,
            login_hint: None,
            claims: None,
            nonce: None,
        }
    }

    pub fn authority(&'a mut self, authority: &'a str) -> &'a mut AuthorizationUrl {
        self.authority = Some(authority);
        self
    }

    pub fn response_mode(&'a mut self, response_mode: &'a str) -> &'a mut AuthorizationUrl {
        self.response_mode = Some(response_mode);
        self
    }

    pub fn code_challenge(&'a mut self, code_challenge: &'a str) -> &'a mut AuthorizationUrl {
        self.response_mode = Some(code_challenge);
        self
    }

    pub fn code_challenge_method(
        &'a mut self,
        code_challenge_method: &'a str,
    ) -> &'a mut AuthorizationUrl {
        self.response_mode = Some(code_challenge_method);
        self
    }

    pub fn state(&'a mut self, state: &'a str) -> &'a mut AuthorizationUrl {
        self.response_mode = Some(state);
        self
    }

    pub fn prompt(&'a mut self, prompt: &'a str) -> &'a mut AuthorizationUrl {
        self.prompt = Some(prompt);
        self
    }

    pub fn login_hint(&'a mut self, login_hint: &'a str) -> &'a mut AuthorizationUrl {
        self.login_hint = Some(login_hint);
        self
    }

    pub fn claims(&'a mut self, claims: &'a str) -> &'a mut AuthorizationUrl {
        self.claims = Some(claims);
        self
    }

    pub fn nonce(&'a mut self, nonce: &'a str) -> &'a mut AuthorizationUrl {
        self.nonce = Some(nonce);
        self
    }

    pub fn build(&self) -> String {
        let mut params: HashMap<&str, &str> = HashMap::new();
        params.insert(CLIENT_ID, self.client_id);
        params.insert(REDIRECT_URI, self.redirect_uri);
        params.insert(RESPONSE_TYPE, CODE);

        let scopes = &self.scopes.join(" ");
        params.insert(SCOPES, scopes);

        let response_mode;
        if let Some(x) = self.response_mode {
            response_mode = x;
        } else {
            response_mode = "query";
        }
        params.insert(RESPONSE_MODE, response_mode);

        if let Some(x) = self.code_challenge {
            params.insert(CODE_CHALLENGE, x);
        }

        if let Some(x) = self.code_challenge_method {
            params.insert(CODE_CHALLENGE_METHOD, x);
        }

        if let Some(x) = self.state {
            params.insert(STATE, x);
        }

        if let Some(x) = self.prompt {
            params.insert(PROMPT, x);
        }

        if let Some(x) = self.login_hint {
            params.insert(LOGIN_HINT, x);
        }

        if let Some(x) = self.claims {
            params.insert(CLAIMS, x);
        }

        if let Some(x) = self.nonce {
            params.insert(NONCE, x);
        }

        let encoded_query = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(params)
            .finish();

        let authority = if let Some(x) = self.authority {
            x
        } else {
            COMMON_AUTHORITY
        };

        let auth_url = format!("{}/oauth2/v2.0/authorize?{}", authority, encoded_query);
        auth_url
    }
}

pub enum ResponseMode {}

#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    pub expires_in: Option<u64>,
    pub ext_expires_in: Option<u64>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,

    // Error
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub error_codes: Option<Vec<usize>>,
    pub timestamp: Option<String>,
    pub trace_id: Option<String>,
    pub correlation_id: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct DeviceCodeResponse {
    pub user_code: String,
    pub device_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
    pub message: String,
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
        scopes: &Vec<&str>,
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
            http_post(&self.authority.device_code_endpoint, request_body)
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
                http_post(&self.authority.token_endpoint, device_code_body.clone()).unwrap();

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
        return &self.client_id;
    }

    fn authority(&self) -> &Authority {
        return &self.authority;
    }
}

impl ClientApplication for ConfidentialClient<'_> {
    fn client_id(&self) -> &str {
        return &self.client_id;
    }

    fn authority(&self) -> &Authority {
        return &self.authority;
    }
}
fn http_get(url: &str) -> Result<reqwest::blocking::Response, reqwest::Error> {
    reqwest::blocking::get(url)
}

fn http_post(url: &str, body: String) -> Result<reqwest::blocking::Response, reqwest::Error> {
    let client = reqwest::blocking::Client::new();
    client.post(url).body(body).send()
}

#[derive(Deserialize)]
struct TenantDiscoveryResponse {
    authorization_endpoint: String,
    token_endpoint: String,
}

pub struct Authority {
    pub authority_url: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub device_code_endpoint: String,
}

impl Authority {
    pub fn new(authority_url: &str) -> Self {
        let tenant_discovery_response = Self::tenant_discovery(&authority_url);

        Authority {
            authority_url: authority_url.to_string(),
            authorization_endpoint: tenant_discovery_response.authorization_endpoint,
            token_endpoint: tenant_discovery_response.token_endpoint.clone(),
            device_code_endpoint: tenant_discovery_response
                .token_endpoint
                .replace("token", "devicecode"),
        }
    }

    fn tenant_discovery(authority_url: &str) -> TenantDiscoveryResponse {
        let response = http_get(&format!("{}{}", authority_url, TENANT_DISCOVERY_ENDPOINT));
        let response: TenantDiscoveryResponse = response.unwrap().json().unwrap();
        response
    }
}
