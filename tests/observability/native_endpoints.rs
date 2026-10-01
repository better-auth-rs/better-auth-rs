use super::*;
use better_auth::plugins::email_otp::EmailOtpCallbacks;
use better_auth::plugins::{EmailOtpPlugin, EmailOtpType, JwtPlugin, TwoFactorPlugin};

#[tokio::test]
async fn native_endpoint_spans_share_real_operation_ids_and_error_boundaries() -> AuthResult<()> {
    let auth = BetterAuth::stateless(config())
        .hooks(EndpointHooks {
            before: Some(Arc::new(UserHooks)),
            after: Some(Arc::new(UserHooks)),
        })
        .plugin(
            EmailOtpPlugin::new().callbacks(EmailOtpCallbacks::<S>::default().generate(
                |email, _, _| {
                    if email == "ordinary@example.test" {
                        Err(AuthError::internal("ordinary failure"))
                    } else {
                        Ok(Some("123456".into()))
                    }
                },
            )),
        )
        .plugin(JwtPlugin::new())
        .plugin(TwoFactorPlugin::new())
        .plugin(Probe)
        .build()
        .await?;
    for operation in [
        "generateTOTP",
        "viewBackupCodes",
        "createEmailVerificationOTP",
        "getEmailVerificationOTP",
        "signJWT",
        "verifyJWT",
        "invalid",
        "ordinary",
        "request-method",
    ] {
        let capture = Capture::default();
        let result: AuthResult<()> = async {
            match operation {
                "request-method" => {
                    let request = AuthRequest::new(HttpMethod::Patch, "/original");
                    let _ = auth
                        .two_factor()?
                        .with_request(better_auth_core::NativeRequest {
                            request: Some(&request),
                            headers: None,
                        })
                        .generate_totp(Some(json!({"secret":"fixture"})))
                        .await?;
                }
                "generateTOTP" => {
                    let _ = auth
                        .two_factor()?
                        .generate_totp(Some(json!({"secret":"fixture"})))
                        .await?;
                }
                "viewBackupCodes" => {
                    let _ = auth
                        .two_factor()?
                        .view_backup_codes(Some(json!({"userId":"missing"})))
                        .await?;
                }
                "createEmailVerificationOTP" => {
                    let _ = auth
                        .email_otp()?
                        .create("fixture@example.test", EmailOtpType::SignIn)
                        .await?;
                }
                "getEmailVerificationOTP" => {
                    let _ = auth
                        .email_otp()?
                        .get("fixture@example.test", EmailOtpType::SignIn)
                        .await?;
                }
                "signJWT" => {
                    let _ = auth.jwt()?.sign(Map::new()).await?;
                }
                "verifyJWT" => {
                    let _ = auth.jwt()?.verify("invalid", None).await?;
                }
                "invalid" => {
                    let _ = auth
                        .two_factor()?
                        .generate_totp(Some(json!({"secret":7})))
                        .await?;
                }
                "ordinary" => {
                    let _ = auth
                        .email_otp()?
                        .create("ordinary@example.test", EmailOtpType::SignIn)
                        .await?;
                }
                _ => return Err(AuthError::internal("Unknown native span test operation")),
            }
            Ok(())
        }
        .instrument(capture.span())
        .await;
        let failed = matches!(operation, "viewBackupCodes" | "invalid" | "ordinary");
        assert_eq!(result.is_err(), failed);
        let method = if operation == "request-method" {
            "PATCH"
        } else if operation == "getEmailVerificationOTP" {
            "GET"
        } else {
            "POST"
        };
        let op = match operation {
            "invalid" | "request-method" => "generateTOTP",
            "ordinary" => "createEmailVerificationOTP",
            _ => operation,
        };
        let outer = format!("{method} /:virtual");
        let records = capture
            .0
            .lock()
            .map_err(|_| AuthError::internal("capture poisoned"))?;
        let endpoints: Vec<_> = records
            .iter()
            .filter(|record| record.fields.contains_key("http.route"))
            .collect();
        let mut expected = vec![
            outer.as_str(),
            "hook before /:virtual user",
            "hook before /:virtual plugin:observe",
            "handler /:virtual",
        ];
        if operation != "ordinary" {
            expected.extend([
                "hook after /:virtual user",
                "hook after /:virtual plugin:observe",
            ]);
        }
        assert_eq!(
            endpoints
                .iter()
                .filter_map(|record| record.fields.get("otel.name").and_then(Value::as_str))
                .collect::<Vec<_>>(),
            expected
        );
        for record in &endpoints {
            assert_eq!(record.fields.get("http.route"), Some(&json!("/:virtual")));
            assert_eq!(
                record.fields.get("better_auth.operation_id"),
                Some(&json!(op))
            );
            assert_eq!(record.closed, 1);
        }
        let handler = endpoints
            .iter()
            .find(|record| record.fields.get("otel.name") == Some(&json!("handler /:virtual")))
            .expect("native handler span");
        assert_eq!(handler.parent.as_deref(), Some(outer.as_str()));
        assert_eq!(handler.exceptions.len(), usize::from(failed));
    }
    Ok(())
}
