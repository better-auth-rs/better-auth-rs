use better_auth::AuthConfig;

pub fn configure(profile: &str, config: &mut AuthConfig) {
    if matches!(profile, "http-body-csrf-explicit" | "http-body-csrf-legacy") {
        config.advanced.disable_origin_check = true;
        config.advanced.disable_csrf_check =
            (profile == "http-body-csrf-explicit").then_some(false);
    }
}
