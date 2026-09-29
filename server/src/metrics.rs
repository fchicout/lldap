use crate::tcp_server::AppState;
use actix_web::{HttpResponse, Responder, web};
use chrono::Utc;
use lldap_access_control::ReadonlyBackendHandler;
use lldap_domain_handlers::handler::BackendHandler;
use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};

pub async fn metrics_handler<Backend>(
    data: web::Data<AppState<Backend>>,
) -> actix_web::Result<impl Responder>
where
    Backend: BackendHandler + Clone + 'static,
{
    let registry = Registry::new();
    let encoder = TextEncoder::new();

    let g_users = GaugeVec::new(
        Opts::new(
            "lldap_directory_users_total",
            "Total registered user accounts",
        ),
        &[],
    )
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let g_groups = GaugeVec::new(
        Opts::new("lldap_directory_groups_total", "Total registered groups"),
        &[],
    )
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let g_group_members = GaugeVec::new(
        Opts::new(
            "lldap_directory_group_members_total",
            "Total members per group",
        ),
        &["group"],
    )
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let g_mfa = GaugeVec::new(
        Opts::new(
            "lldap_security_mfa_users_total",
            "Users count grouped by MFA type",
        ),
        &["mfa_type"],
    )
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let g_password_age = GaugeVec::new(
        Opts::new(
            "lldap_credential_password_age_seconds",
            "Age of user password in seconds",
        ),
        &["user_id"],
    )
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let g_stale_passwords = GaugeVec::new(
        Opts::new(
            "lldap_credential_stale_passwords_total",
            "Users exceeding password rotation threshold",
        ),
        &["threshold"],
    )
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let g_jwt_blacklist = GaugeVec::new(
        Opts::new(
            "lldap_security_jwt_sessions_blacklisted_total",
            "Total blacklisted or revoked JWT sessions in memory",
        ),
        &[],
    )
    .map_err(actix_web::error::ErrorInternalServerError)?;

    registry
        .register(Box::new(g_users.clone()))
        .map_err(actix_web::error::ErrorInternalServerError)?;
    registry
        .register(Box::new(g_groups.clone()))
        .map_err(actix_web::error::ErrorInternalServerError)?;
    registry
        .register(Box::new(g_group_members.clone()))
        .map_err(actix_web::error::ErrorInternalServerError)?;
    registry
        .register(Box::new(g_mfa.clone()))
        .map_err(actix_web::error::ErrorInternalServerError)?;
    registry
        .register(Box::new(g_password_age.clone()))
        .map_err(actix_web::error::ErrorInternalServerError)?;
    registry
        .register(Box::new(g_stale_passwords.clone()))
        .map_err(actix_web::error::ErrorInternalServerError)?;
    registry
        .register(Box::new(g_jwt_blacklist.clone()))
        .map_err(actix_web::error::ErrorInternalServerError)?;

    // JWT Blacklist from AppState
    if let Ok(blacklist) = data.jwt_blacklist.read() {
        g_jwt_blacklist
            .with_label_values(&[])
            .set(blacklist.len() as f64);
    }

    let handler = data.get_readonly_handler();
    let now = Utc::now().naive_utc();

    // Query Users (reusing database connection pool via Sea-ORM domain handler)
    if let Ok(users) = handler.list_users(None, true).await {
        g_users.with_label_values(&[]).set(users.len() as f64);

        let mut stale_90d = 0.0;
        let mut stale_180d = 0.0;

        for user_and_groups in &users {
            let user = &user_and_groups.user;
            let mfa_label = "none";
            g_mfa.with_label_values(&[mfa_label]).inc();

            let age_duration = now.signed_duration_since(user.password_modified_date);
            let secs = age_duration.num_seconds().max(0) as f64;
            g_password_age
                .with_label_values(&[user.user_id.as_str()])
                .set(secs);

            if secs > 90.0 * 86400.0 {
                stale_90d += 1.0;
            }
            if secs > 180.0 * 86400.0 {
                stale_180d += 1.0;
            }
        }
        g_stale_passwords.with_label_values(&["90d"]).set(stale_90d);
        g_stale_passwords
            .with_label_values(&["180d"])
            .set(stale_180d);
    }

    // Query Groups (reusing database connection pool)
    if let Ok(groups) = handler.list_groups(None).await {
        g_groups.with_label_values(&[]).set(groups.len() as f64);
        for group in &groups {
            g_group_members
                .with_label_values(&[group.display_name.as_str()])
                .set(group.users.len() as f64);
        }
    }

    let mut buffer = Vec::new();
    encoder
        .encode(&registry.gather(), &mut buffer)
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(buffer))
}
