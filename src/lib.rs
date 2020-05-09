use serde::Deserialize;

pub fn http_get(url: &str) -> Result<reqwest::blocking::Response, reqwest::Error> {
     reqwest::blocking::get(url)
}

pub fn http_post(url: &str, body: String) -> Result<reqwest::blocking::Response, reqwest::Error> {
    let client = reqwest::blocking::Client::new();
    client.post(url).body(body).send()
}

const TENANT_DISCOVERY_ENDPOINT: &'static str = "/v2.0/.well-known/openid-configuration";

#[derive(Deserialize)]
struct TenantDiscoveryResponse {
    authorization_endpoint: String,
    token_endpoint: String
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
            device_code_endpoint: tenant_discovery_response.token_endpoint.replace("token", "devicecode"),
        }
    }

    fn tenant_discovery(authority_url: &str) -> TenantDiscoveryResponse {

        let response = http_get(&format!("{}{}" , authority_url, TENANT_DISCOVERY_ENDPOINT));
        let response: TenantDiscoveryResponse = response.unwrap().json().unwrap();
        response
    }
}