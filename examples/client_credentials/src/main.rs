use msal::{ClientCredential, ConfidentialClient};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // configuration
    let authority = "https://login.microsoftonline.com/sgonz.onmicrosoft.com";
    let client_id = "6c04f413-f6e7-4690-b372-dbdd083e7e5a";
    let scopes: Vec<&str> = vec!["user.read"];

    let secret = "";
    let client_credential = msal::ClientCredential::from_secret(secret);

    let pca = ConfidentialClient::new(client_id, authority, client_credential);
    let resp = pca.acquire_token_for_client(&scopes);

    println!("{}", &resp.access_token.unwrap());
    Ok(())
}
