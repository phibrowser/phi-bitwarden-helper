// Verifies that `ClientSettings.bitwarden_client_version` reaches the wire as
// the `Bitwarden-Client-Version` header on identity requests. The identity
// server rejects logins without it ("No client version header found, required
// to prevent encryption errors"), and the header is sourced from the settings
// passed to `PasswordManagerClient::new` — NOT from `init_host_platform_info`,
// which only feeds `GlobalClient`. This probe exists because that distinction
// was missed once already.
//
// Debug builds only (release enforces https_only, which blocks the local
// plain-HTTP capture): cargo run --example header_probe --features bitwarden-sdk

use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let capture = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 16384];
        let n = s.read(&mut buf).unwrap_or(0);
        let _ = s.write_all(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n");
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    let settings = bitwarden_core::ClientSettings {
        identity_url: format!("http://127.0.0.1:{port}/identity"),
        api_url: format!("http://127.0.0.1:{port}/api"),
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
    let _ = rt.block_on(async {
        client
            .0
            .auth()
            .login_password(&bitwarden_core::auth::login::PasswordLoginRequest {
                email: "probe@example.com".to_string(),
                password: "probe".to_string(),
                two_factor: None,
            })
            .await
    });

    let request = capture.join().unwrap();
    println!("---- captured request ----\n{request}\n--------------------------");
    let ok = request
        .to_lowercase()
        .contains("bitwarden-client-version: 2026.6.0");
    println!("Bitwarden-Client-Version header present: {ok}");
    std::process::exit(if ok { 0 } else { 1 });
}
