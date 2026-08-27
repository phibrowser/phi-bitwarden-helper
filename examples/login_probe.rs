// Diagnostic: run a real password login through a local identity proxy so the
// response *shape* can be inspected (the proxy logs field names only). Reads
// credentials from BW_CREDS_FILE (email + master password, whitespace-split)
// and the proxy base URL from BW_IDENTITY_URL. Debug builds only (release
// enforces https_only). Never prints credentials or tokens.
//
//   BW_CREDS_FILE=... BW_IDENTITY_URL=http://127.0.0.1:19980/identity \
//     cargo run --example login_probe --features bitwarden-sdk

fn main() {
    let creds_path = std::env::var("BW_CREDS_FILE").expect("BW_CREDS_FILE not set");
    let identity_url = std::env::var("BW_IDENTITY_URL").expect("BW_IDENTITY_URL not set");
    let raw = std::fs::read_to_string(creds_path).expect("cannot read creds file");
    let mut parts = raw.split_whitespace();
    let email = parts.next().expect("missing email").to_string();
    let password = parts.next().expect("missing password").to_string();

    let settings = bitwarden_core::ClientSettings {
        identity_url,
        api_url: "https://api.bitwarden.com".to_string(),
        user_agent: "PhiBitwardenHelper/probe".to_string(),
        device_type: bitwarden_core::DeviceType::MacOsCLI,
        device_identifier: Some("11111111-2222-4333-8444-555555555555".to_string()),
        bitwarden_client_version: Some("2026.6.0".to_string()),
        bitwarden_package_type: Some("cli".to_string()),
    };
    let client = bitwarden_pm::PasswordManagerClient::new(Some(settings));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = rt.block_on(async {
        client
            .0
            .auth()
            .login_password(&bitwarden_core::auth::login::PasswordLoginRequest {
                email,
                password,
                two_factor: None,
                new_device_otp: None,
            })
            .await
    });
    match result {
        Ok(r) => println!(
            "login ok: authenticated={} force_password_reset={} two_factor={:?}",
            r.authenticated, r.force_password_reset, r.two_factor
        ),
        Err(e) => println!("login error: {e}"),
    }
}
