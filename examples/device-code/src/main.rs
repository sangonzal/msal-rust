use msal::DeviceCodeResponse;
use msal::PublicClient;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let authority = "https://login.microsoftonline.com/sgonz.onmicrosoft.com";
    let client_id = "6c04f413-f6e7-4690-b372-dbdd083e7e5a";
    let scopes: Vec<&str> = vec!["user.read", "offline_access", "openid"];

    let pca = PublicClient::new(client_id, authority);

    let resp =
        pca.acquire_token_by_device_flow(&scopes, |device_code_response: DeviceCodeResponse| {
            println!("{}", device_code_response.message);
        });

    println!("{}", &resp?.refresh_token.unwrap());
    Ok(())
}
