use msal::ClientApplication;
use msal::PublicClient;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // configuration
    let authority = "https://login.microsoftonline.com/sgonz.onmicrosoft.com";
    let client_id = "6c04f413-f6e7-4690-b372-dbdd083e7e5a";
    let scopes: Vec<&str> = vec!["user.read"];
    let refresh_token = "";

    let pca = PublicClient::new(client_id, authority);
    let resp = pca.acquire_token_by_refresh_token(&scopes, refresh_token);

    println!("{}", &resp.access_token.unwrap());
    Ok(())
}
