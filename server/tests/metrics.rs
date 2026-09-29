use crate::common::{
    env,
    fixture::{LLDAPFixture, User, new_id},
};
use reqwest::blocking::ClientBuilder;
use serial_test::file_serial;
mod common;

#[test]
#[file_serial]
fn test_prometheus_metrics_endpoint() {
    let mut fixture = LLDAPFixture::new();
    let prefix = "metrics-test-";
    let user1_name = new_id(Some(prefix));
    let group1_name = new_id(Some(prefix));
    let initial_state = vec![User::new(&user1_name, vec![&group1_name])];
    fixture.load_state(&initial_state);

    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");

    let metrics_url = format!("{}/metrics", env::http_url());
    let response = client
        .get(&metrics_url)
        .send()
        .expect("failed to request /metrics");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .expect("missing content-type header")
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/plain"));

    let body = response.text().expect("failed to read response text");
    assert!(body.contains("lldap_directory_users_total"));
    assert!(body.contains("lldap_directory_groups_total"));
    assert!(body.contains("lldap_directory_group_members_total"));
    assert!(body.contains("lldap_security_mfa_users_total"));
    assert!(body.contains("lldap_credential_password_age_seconds"));
    assert!(body.contains("lldap_credential_stale_passwords_total"));
    assert!(body.contains("lldap_security_jwt_sessions_blacklisted_total"));
}
