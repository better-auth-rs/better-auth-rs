use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::plugins::{
    ApiKeyConfig, ApiKeyPlugin, LastLoginMethodConfig, LastLoginMethodPlugin, OpenApiConfig,
    OpenApiPlugin, OrganizationConfig, OrganizationPlugin, UsernameConfig, UsernamePlugin,
    api_key::RateLimitDefaults, organization::OrganizationTeamsConfig,
};
use better_auth::{AuthConfig, BetterAuth, server_api::EndpointInput};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema, BaseUrl,
    DynamicBaseUrl, HttpMethod,
    middleware::{RateLimitConfig, RateLimitStorageKind},
    openapi::{OpenApiPluginMetadata, OpenApiRouteMetadata},
    organization_fields::OrganizationFields,
    store::{MemoryCacheAdapter, StatelessSchema},
    user_fields::{UserConfig, UserFieldConfig, UserFieldType},
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Input {
    profile: String,
    hosts: Option<Vec<String>>,
}

struct DocsProbe;

fn metadata(id: Option<&str>) -> OpenApiRouteMetadata {
    OpenApiRouteMetadata {
        operation_id: id.map(str::to_owned),
        ..Default::default()
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for DocsProbe {
    fn name(&self) -> &'static str {
        "docs-probe"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut both = metadata(Some("duplicate"));
        both.description = Some("Probe".into());
        both.parameters = Some(vec![
            json!({"name":"page","in":"query","schema":{"type":"number"}}),
            json!({"name":"value","in":"query","schema":{"type":"string"}}),
        ]);
        both.request_body = Some(
            json!({"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"optional":{"type":"string"}}}}}}),
        );
        let mut same = metadata(Some("duplicate"));
        same.parameters = Some(Vec::new());
        let _ = same
            .responses
            .insert("400".into(), json!({"description":"Custom failure"}));
        let mut server = metadata(None);
        server.server_only = true;
        let mut routes = vec![
            AuthRoute::get("/docs-probe/{id}", "both")
                .endpoint_key("both")
                .openapi(both.clone()),
            AuthRoute::post("/docs-probe/{id}", "both")
                .endpoint_key("both")
                .openapi(both),
            AuthRoute::get("/docs-second", "same")
                .endpoint_key("same")
                .openapi(same),
            AuthRoute::get("/docs-third", "third")
                .endpoint_key("third")
                .openapi(metadata(Some("duplicate"))),
            AuthRoute::get("/docs-scoped", "scope")
                .endpoint_key("scope")
                .openapi(metadata(None)),
            AuthRoute::get("/docs-server", "server")
                .endpoint_key("server")
                .openapi(server),
        ];
        let mut mixed = metadata(Some("mixed"));
        mixed.parameters = Some(vec![
            json!({"name":"filter","in":"query","schema":{"type":"string"}}),
        ]);
        mixed.request_body = Some(
            json!({"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"value":{"type":"string"}},"required":["value"]}}}}),
        );
        for method in [
            HttpMethod::Patch,
            HttpMethod::Delete,
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Head,
            HttpMethod::Options,
        ] {
            routes.insert(
                routes.len() - 2,
                AuthRoute::new(method, "/docs-methods", "mixed")
                    .endpoint_key("mixed")
                    .openapi(mixed.clone()),
            );
        }
        routes.insert(
            routes.len() - 2,
            AuthRoute::get("/docs-core-collision", "getSession")
                .endpoint_key("getSession")
                .openapi(metadata(None)),
        );
        routes
    }

    fn openapi(&self) -> AuthResult<OpenApiPluginMetadata> {
        let fields = UserConfig {
            additional_fields: Some(
                [
                    (
                        "title".into(),
                        UserFieldConfig {
                            required: Some(true),
                            input: Some(false),
                            ..Default::default()
                        },
                    ),
                    (
                        "hidden".into(),
                        UserFieldConfig {
                            required: Some(true),
                            returned: Some(false),
                            ..Default::default()
                        },
                    ),
                    (
                        "payload".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Json,
                            ..Default::default()
                        },
                    ),
                    (
                        "category".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Enum(vec!["staff".into(), "guest".into()]),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        };
        Ok(
            OpenApiPluginMetadata::from_routes(
                "docs-probe",
                <Self as AuthPlugin<S>>::routes(self),
            )?
            .model("widget", &fields)?,
        )
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if <Self as AuthPlugin<S>>::routes(self)
            .iter()
            .any(|route| route.matches(request.method(), request.path()))
        {
            Ok(Some(AuthResponse::json(200, &json!({"ok":true}))?))
        } else {
            Ok(None)
        }
    }
}

fn request(url: &str) -> AuthRequest {
    let url = url::Url::parse(url).unwrap();
    AuthRequest::new(HttpMethod::Get, url.path()).with_url(url)
}

fn response(result: AuthResult<AuthResponse>) -> AuthResponse {
    match result {
        Ok(response) => response,
        Err(error) if error.is_api_error() => error.to_auth_response(),
        Err(error) => panic!("Unexpected OpenAPI fixture failure: {error}"),
    }
}

async fn invoke(auth: &BetterAuth<StatelessSchema>, host: &str, reference_path: &str) -> Value {
    let schema_url = format!("https://{host}/api/auth/open-api/generate-schema");
    let schema = response(auth.handle_request(request(&schema_url)).await);
    let native = response(
        auth.call_endpoint(
            HttpMethod::Get,
            "/open-api/generate-schema",
            EndpointInput {
                request: Some(request(&schema_url)),
                ..Default::default()
            },
        )
        .await,
    );
    let reference_url = format!("https://{host}/api/auth{reference_path}");
    let reference = response(auth.handle_request(request(&reference_url)).await);
    let native_reference = response(
        auth.call_endpoint(
            HttpMethod::Get,
            reference_path,
            EndpointInput {
                request: Some(request(&reference_url)),
                ..Default::default()
            },
        )
        .await,
    );
    json!({
        "host":host,"status":schema.status,
        "schema":serde_json::from_slice::<Value>(&schema.body).unwrap(),
        "native":serde_json::from_slice::<Value>(&native.body).unwrap(),
        "reference":{"status":reference.status,"body":String::from_utf8(reference.body).unwrap(),"contentType":reference.headers.get("content-type"),"csp":reference.headers.get("content-security-policy")},
        "nativeReference":{"status":native_reference.status,"body":String::from_utf8(native_reference.body).unwrap(),"contentType":native_reference.headers.get("content-type")}
    })
}

async fn run(input: Input) -> AuthResult<Value> {
    let metadata = input.profile == "metadata";
    let disabled = input.profile == "disabled";
    let models = input.profile.starts_with("models-");
    let full_models = models && input.profile != "models-minimal";
    let secondary = input.profile.starts_with("models-secondary");
    let defaults = Arc::new(AtomicUsize::new(0));
    let mut config = AuthConfig::new(
        "openapi-schema-fixture-secret-at-least-thirty-two-characters",
    )
    .base_url(BaseUrl::Dynamic(DynamicBaseUrl {
        allowed_hosts: vec!["*.tenant.test".into()],
        fallback: None,
        protocol: None,
    }));
    config.disabled_paths = if metadata {
        vec!["/ok".into()]
    } else if disabled {
        vec![
            "/sign-in/email".into(),
            "/delete-user".into(),
            "/get-session".into(),
        ]
    } else {
        Vec::new()
    };
    if metadata {
        let counter = defaults.clone();
        config.user.additional_fields = Some([
            (
                "requiredTag".into(),
                UserFieldConfig {
                    required: Some(true),
                    ..Default::default()
                },
            ),
            (
                "hidden".into(),
                UserFieldConfig {
                    required: Some(true),
                    input: Some(false),
                    returned: Some(false),
                    ..Default::default()
                },
            ),
            (
                "factory".into(),
                UserFieldConfig {
                    required: Some(true),
                    default_value_fn: Some(Arc::new(move || {
                        let _ = counter.fetch_add(1, Ordering::SeqCst);
                        json!("factory")
                    })),
                    ..Default::default()
                },
            ),
            (
                "array".into(),
                UserFieldConfig {
                    field_type: UserFieldType::NumberArray,
                    default_value: Some(json!([1])),
                    ..Default::default()
                },
            ),
            (
                "jsonOracle".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Json,
                    default_value: Some(serde_json::from_str(r#"{"4294967295":"last-index","01":"leading-zero","4294967294":1e21,"0":-0.0,"numbers":[0.0,-0.0,1e-7,1e-6,1e20,1e21],"nested":{"2":2.0,"1":1.0,"01":1.0}}"#).unwrap()),
                    ..Default::default()
                },
            ),
            (
                "payload".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Json,
                    ..Default::default()
                },
            ),
            (
                "category".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Enum(vec!["staff".into(), "guest".into()]),
                    ..Default::default()
                },
            ),
        ]
        .into());
    }
    if models {
        config.user.additional_fields = Some(
            [(
                "username".into(),
                UserFieldConfig {
                    required: Some(true),
                    default_value: Some(json!("app-username")),
                    ..Default::default()
                },
            )]
            .into(),
        );
        config.session.additional_fields = Some(
            [(
                "tenantLabel".into(),
                UserFieldConfig {
                    required: Some(true),
                    default_value: Some(json!("session")),
                    ..Default::default()
                },
            )]
            .into(),
        );
    }
    config.verification.store_in_database = input.profile == "models-secondary-database";
    let mut rate_limit = RateLimitConfig::new().enabled(false);
    if secondary {
        rate_limit = rate_limit.storage(RateLimitStorageKind::Database);
    }
    let mut builder = BetterAuth::stateless(config).rate_limit(rate_limit);
    if secondary {
        builder = builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()));
    }
    if models {
        let counter = defaults.clone();
        let schema = OrganizationFields {
            organization: UserConfig {
                additional_fields: Some(
                    [
                        (
                            "label".into(),
                            UserFieldConfig {
                                required: Some(true),
                                default_value: Some(json!("org-default")),
                                ..Default::default()
                            },
                        ),
                        (
                            "optionalTag".into(),
                            UserFieldConfig {
                                required: Some(false),
                                ..Default::default()
                            },
                        ),
                        (
                            "hidden".into(),
                            UserFieldConfig {
                                input: Some(false),
                                returned: Some(false),
                                ..Default::default()
                            },
                        ),
                        (
                            "factory".into(),
                            UserFieldConfig {
                                default_value_fn: Some(Arc::new(move || {
                                    let _ = counter.fetch_add(1, Ordering::SeqCst);
                                    json!("factory")
                                })),
                                ..Default::default()
                            },
                        ),
                    ]
                    .into(),
                ),
            },
            member: UserConfig {
                additional_fields: Some(
                    [(
                        "badge".into(),
                        UserFieldConfig {
                            required: Some(false),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
            invitation: UserConfig {
                additional_fields: Some(
                    [(
                        "comment".into(),
                        UserFieldConfig {
                            required: Some(false),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
            team: UserConfig {
                additional_fields: Some(
                    [(
                        "teamTag".into(),
                        UserFieldConfig {
                            required: Some(true),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
            organization_role: UserConfig {
                additional_fields: Some(
                    [(
                        "roleTag".into(),
                        UserFieldConfig {
                            required: Some(true),
                            default_value: Some(json!("role-default")),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        };
        let organization = OrganizationPlugin::with_config(OrganizationConfig {
            schema,
            teams: OrganizationTeamsConfig {
                enabled: full_models,
                ..Default::default()
            },
            dynamic_access_control: full_models,
            ..Default::default()
        })
        .access_control(
            [
                (
                    "organization".into(),
                    vec!["update".into(), "delete".into()],
                ),
                (
                    "member".into(),
                    vec!["create".into(), "update".into(), "delete".into()],
                ),
                ("invitation".into(), vec!["create".into(), "cancel".into()]),
                (
                    "team".into(),
                    vec!["create".into(), "update".into(), "delete".into()],
                ),
                (
                    "ac".into(),
                    vec![
                        "create".into(),
                        "read".into(),
                        "update".into(),
                        "delete".into(),
                    ],
                ),
            ]
            .into(),
        );
        let mut key = ApiKeyPlugin::with_config(ApiKeyConfig {
            config_id: if secondary { "first" } else { "default" }.into(),
            rate_limit: RateLimitDefaults {
                max_requests: 7.0,
                time_window: 1234.0,
                ..Default::default()
            },
            ..Default::default()
        });
        if secondary {
            key = key.configuration(ApiKeyConfig {
                config_id: "second".into(),
                ..Default::default()
            });
        }
        builder = builder
            .plugin(organization)
            .plugin(UsernamePlugin::new(UsernameConfig {
                display_username: full_models,
                ..Default::default()
            }))
            .plugin(LastLoginMethodPlugin::new(LastLoginMethodConfig {
                store_in_database: full_models,
                ..Default::default()
            }))
            .plugin(key);
    }
    if metadata {
        builder = builder.plugin(DocsProbe);
    }
    let reference_path = if metadata { "/docs" } else { "/reference" };
    let auth = Arc::new(
        builder
            .plugin(OpenApiPlugin::with_config(OpenApiConfig {
                path: reference_path.into(),
                disable_default_reference: disabled,
                theme: metadata.then(|| "moon".into()),
                nonce: metadata.then(|| "probe-nonce".into()),
            }))
            .build()
            .await?,
    );
    let mut pending = Vec::new();
    for host in input.hosts.unwrap_or_else(|| vec!["a.tenant.test".into()]) {
        let auth = auth.clone();
        pending.push(tokio::spawn(async move {
            invoke(&auth, &host, reference_path).await
        }));
    }
    let mut calls = Vec::new();
    for call in pending {
        calls.push(call.await.unwrap());
    }
    Ok(json!({"calls":calls,"defaultCalls":defaults.load(Ordering::SeqCst)}))
}

pub fn router() -> Router {
    Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/__test/reset-state",
            post(|| async { Json(json!({"success":true})) }),
        )
        .route(
            "/__test/openapi",
            post(|Json(input): Json<Input>| async move { run(input).await.map(Json) }),
        )
}
