use better_auth_core::{AuthError, AuthResult};

use super::super::{CognitoOptions, GoogleOptions, TwitchOptions, google};
use super::{OAuthProvider, ProviderKind};

impl OAuthProvider {
    /// Configure Social Microsoft with its tenant, authority, photo, and assertion options.
    pub fn microsoft(
        client_id: &str,
        client_secret: &str,
        options: super::microsoft::MicrosoftOptions,
    ) -> AuthResult<Self> {
        if !client_secret.is_empty() && options.client_assertion.is_some() {
            return Err(AuthError::internal(
                "Microsoft Entra ID clientAssertion cannot be combined with clientSecret",
            ));
        }
        let authorization = format!(
            "{}/{}/oauth2/v2.0/authorize",
            options.authority(),
            options.tenant()
        );
        let token = format!(
            "{}/{}/oauth2/v2.0/token",
            options.authority(),
            options.tenant()
        );
        let token_endpoint_auth = options
            .client_assertion
            .clone()
            .map(super::TokenEndpointAuth::PrivateKeyJwt);
        Ok(Self {
            kind: ProviderKind::Microsoft {
                options,
                token_endpoint_auth,
            },
            ..Self::custom(client_id, client_secret, &authorization, &token)
        })
    }

    /// Configure a Cognito hosted domain and its fixed user-pool issuer and JWKS.
    /// Set `identity_provider` through `authorization_params` to select a federated provider.
    pub fn cognito(
        client_id: &str,
        client_secret: &str,
        options: CognitoOptions,
    ) -> AuthResult<Self> {
        if options.domain.is_empty() || options.region.is_empty() || options.user_pool_id.is_empty()
        {
            better_auth_core::observability::logger::current().error(
                "Domain, region and userPoolId are required for Amazon Cognito. Make sure to provide them in the options.",
                &[],
            );
            return Err(AuthError::internal("DOMAIN_AND_REGION_REQUIRED"));
        }
        let domain = options
            .domain
            .strip_prefix("https://")
            .or_else(|| options.domain.strip_prefix("http://"))
            .unwrap_or(&options.domain);
        let provider = Self {
            user_info_url: Some(format!("https://{domain}/oauth2/userinfo")),
            ..Self::custom(
                client_id,
                client_secret,
                &format!("https://{domain}/oauth2/authorize"),
                &format!("https://{domain}/oauth2/token"),
            )
        };
        Ok(Self {
            kind: ProviderKind::Cognito(options),
            ..provider
        })
    }

    /// Configure a custom social provider with explicit endpoints and profile handling.
    pub fn custom(client_id: &str, client_secret: &str, auth_url: &str, token_url: &str) -> Self {
        Self {
            kind: ProviderKind::Custom,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            client_key: None,
            auth_url: auth_url.into(),
            token_url: token_url.into(),
            token_endpoint_auth: None,
            user_info_url: None,
            redirect_uri: None,
            end_session_endpoint: None,
            post_logout_redirect_uri: None,
            scopes: None,
            disable_default_scope: false,
            disable_id_token_sign_in: false,
            prompt: None,
            authorization_params: Vec::new(),
            map_user_info: None,
            map_profile_to_user: None,
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            disable_implicit_sign_up: None,
            disable_sign_up: None,
            require_email_verification: None,
            override_user_info_on_sign_in: false,
        }
    }

    /// Configure Google with its built-in endpoints and profile decoder.
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self::google_with_options(client_id, client_secret, GoogleOptions::default())
    }

    /// Configure Google with additional ID-token audiences.
    pub fn google_with_options(
        client_id: &str,
        client_secret: &str,
        options: GoogleOptions,
    ) -> Self {
        Self {
            kind: ProviderKind::Google {
                jwks_url: google::JWKS_URL.to_owned(),
                options,
            },
            user_info_url: Some("https://www.googleapis.com/oauth2/v3/userinfo".into()),
            authorization_params: vec![("include_granted_scopes".into(), "true".into())],
            ..Self::custom(
                client_id,
                client_secret,
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
            )
        }
    }

    /// Configure GitHub with its built-in profile and email lookup.
    pub fn github(client_id: &str, client_secret: &str) -> Self {
        Self::github_with_endpoints(
            client_id,
            client_secret,
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
            "https://api.github.com/user/emails",
        )
    }

    /// Configure GitHub with custom endpoints while retaining GitHub profile semantics.
    pub fn github_with_endpoints(
        client_id: &str,
        client_secret: &str,
        auth_url: &str,
        token_url: &str,
        user_info_url: &str,
        user_emails_url: &str,
    ) -> Self {
        Self {
            kind: ProviderKind::GitHub {
                user_url: user_info_url.into(),
                emails_url: user_emails_url.into(),
            },
            user_info_url: Some(user_info_url.into()),
            ..Self::custom(client_id, client_secret, auth_url, token_url)
        }
    }

    /// Configure Discord with its built-in endpoints and profile decoder.
    pub fn discord(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Discord,
            user_info_url: Some("https://discord.com/api/users/@me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://discord.com/api/oauth2/authorize",
                "https://discord.com/api/oauth2/token",
            )
        }
    }

    /// Configure GitLab with its built-in endpoints and active-user profile decoder.
    pub fn gitlab(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::GitLab,
            user_info_url: Some("https://gitlab.com/api/v4/user".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://gitlab.com/oauth/authorize",
                "https://gitlab.com/oauth/token",
            )
        }
    }

    /// Configure Spotify with its built-in endpoints and profile decoder.
    pub fn spotify(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Spotify,
            user_info_url: Some("https://api.spotify.com/v1/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://accounts.spotify.com/authorize",
                "https://accounts.spotify.com/api/token",
            )
        }
    }

    /// Configure Hugging Face with its built-in endpoints and HTTP profile decoder.
    pub fn huggingface(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::HuggingFace,
            user_info_url: Some("https://huggingface.co/oauth/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://huggingface.co/oauth/authorize",
                "https://huggingface.co/oauth/token",
            )
        }
    }

    /// Configure Polar with its built-in endpoints and HTTP profile decoder.
    pub fn polar(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Polar,
            user_info_url: Some("https://api.polar.sh/v1/oauth2/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://polar.sh/oauth2/authorize",
                "https://api.polar.sh/v1/oauth2/token",
            )
        }
    }

    /// Configure Vercel with its built-in endpoints and HTTP profile decoder.
    pub fn vercel(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Vercel,
            user_info_url: Some("https://api.vercel.com/login/oauth/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://vercel.com/oauth/authorize",
                "https://api.vercel.com/login/oauth/token",
            )
        }
    }

    /// Configure Figma with PKCE, HTTP Basic token authentication, and its HTTP profile decoder.
    pub fn figma(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Figma,
            user_info_url: Some("https://api.figma.com/v1/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.figma.com/oauth",
                "https://api.figma.com/v1/oauth/token",
            )
        }
    }

    /// Configure Dropbox with PKCE, client-secret-post authentication, and its POST profile lookup.
    pub fn dropbox(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Dropbox,
            user_info_url: Some("https://api.dropboxapi.com/2/users/get_current_account".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.dropbox.com/oauth2/authorize",
                "https://api.dropboxapi.com/oauth2/token",
            )
        }
    }

    /// Configure Kick with PKCE, client-secret-post, and its HTTP profile decoder.
    pub fn kick(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Kick,
            user_info_url: Some("https://api.kick.com/public/v1/users".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://id.kick.com/oauth/authorize",
                "https://id.kick.com/oauth/token",
            )
        }
    }

    /// Configure LinkedIn with its code flow, client-secret-post, and Bearer HTTP profile.
    /// LinkedIn omits PKCE parameters in the pinned provider protocol.
    pub fn linkedin(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::LinkedIn,
            user_info_url: Some("https://api.linkedin.com/v2/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.linkedin.com/oauth/v2/authorization",
                "https://www.linkedin.com/oauth/v2/accessToken",
            )
        }
    }

    /// Configure Slack with its code flow, client-secret-post, and OpenID HTTP profile.
    pub fn slack(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Slack,
            user_info_url: Some("https://slack.com/api/openid.connect.userInfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://slack.com/openid/connect/authorize",
                "https://slack.com/api/openid.connect.token",
            )
        }
    }

    /// Configure Naver with its code flow, client-secret-post, and HTTP profile envelope.
    pub fn naver(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Naver,
            user_info_url: Some("https://openapi.naver.com/v1/nid/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://nid.naver.com/oauth2.0/authorize",
                "https://nid.naver.com/oauth2.0/token",
            )
        }
    }

    /// Configure Social LINE with PKCE and its remote direct ID-token verifier.
    pub fn line(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Line {
                verify_url: "https://api.line.me/oauth2/v2.1/verify".into(),
            },
            user_info_url: Some("https://api.line.me/oauth2/v2.1/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://access.line.me/oauth2/v2.1/authorize",
                "https://api.line.me/oauth2/v2.1/token",
            )
        }
    }

    /// Configure Linear with its code flow, client-secret-post, and GraphQL viewer profile.
    pub fn linear(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Linear,
            user_info_url: Some("https://api.linear.app/graphql".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://linear.app/oauth/authorize",
                "https://api.linear.app/oauth/token",
            )
        }
    }

    /// Configure Atlassian with PKCE, client-secret-post, and its HTTP account profile.
    pub fn atlassian(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Atlassian,
            user_info_url: Some("https://api.atlassian.com/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://auth.atlassian.com/authorize",
                "https://auth.atlassian.com/oauth/token",
            )
        }
    }

    /// Configure Salesforce production with PKCE and its HTTP user-info profile.
    /// Set `auth_url`, `token_url`, and `user_info_url` together for a sandbox or custom login host.
    pub fn salesforce(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Salesforce,
            user_info_url: Some("https://login.salesforce.com/services/oauth2/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://login.salesforce.com/services/oauth2/authorize",
                "https://login.salesforce.com/services/oauth2/token",
            )
        }
    }

    /// Configure Reddit with HTTP Basic token authentication and its API user profile.
    /// Set `duration` to `permanent` through `authorization_params` for persistent access.
    pub fn reddit(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Reddit,
            user_info_url: Some("https://oauth.reddit.com/api/v1/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.reddit.com/api/v1/authorize",
                "https://www.reddit.com/api/v1/access_token",
            )
        }
    }

    /// Configure Kakao with ordered scopes, client-secret-post, and its account profile.
    pub fn kakao(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Kakao,
            user_info_url: Some("https://kapi.kakao.com/v2/user/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://kauth.kakao.com/oauth/authorize",
                "https://kauth.kakao.com/oauth/token",
            )
        }
    }

    /// Configure Zoom with authorization PKCE, client-secret-post, and its HTTP user profile.
    /// The pinned Zoom provider ignores configured and request scopes.
    pub fn zoom(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Zoom { pkce: true },
            user_info_url: Some("https://api.zoom.us/v2/users/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://zoom.us/oauth/authorize",
                "https://zoom.us/oauth/token",
            )
        }
    }

    /// Configure Zoom with its `pkce: false` option for the authorization URL.
    /// Code exchange still forwards the supplied verifier, matching the pinned provider.
    pub fn zoom_without_pkce(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Zoom { pkce: false },
            ..Self::zoom(client_id, client_secret)
        }
    }

    /// Configure Twitter with PKCE, HTTP Basic token authentication, and its two user-info requests.
    pub fn twitter(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Twitter,
            user_info_url: Some(
                "https://api.x.com/2/users/me?user.fields=profile_image_url".into(),
            ),
            ..Self::custom(
                client_id,
                client_secret,
                "https://x.com/i/oauth2/authorize",
                "https://api.x.com/2/oauth2/token",
            )
        }
    }

    /// Configure WeChat WebsiteApp with GET grants and its HTTP profile lookup.
    /// Set `authorization_params`'s `lang` to `en` for the English authorization page.
    pub fn wechat(client_id: &str, client_secret: &str) -> Self {
        Self::wechat_with_endpoints(
            client_id,
            client_secret,
            "https://open.weixin.qq.com/connect/qrconnect",
            "https://api.weixin.qq.com/sns/oauth2/access_token",
            "https://api.weixin.qq.com/sns/oauth2/refresh_token",
            "https://api.weixin.qq.com/sns/userinfo",
        )
    }

    /// Configure WeChat endpoints while retaining its GET grants and profile semantics.
    pub fn wechat_with_endpoints(
        client_id: &str,
        client_secret: &str,
        auth_url: &str,
        token_url: &str,
        refresh_url: &str,
        user_info_url: &str,
    ) -> Self {
        Self {
            kind: ProviderKind::WeChat {
                refresh_url: refresh_url.into(),
            },
            user_info_url: Some(user_info_url.into()),
            ..Self::custom(client_id, client_secret, auth_url, token_url)
        }
    }

    /// Configure VK with PKCE, client-secret-post grants, and form-based user info.
    pub fn vk(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Vk,
            user_info_url: Some("https://id.vk.com/oauth2/user_info".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://id.vk.com/authorize",
                "https://id.vk.com/oauth2/auth",
            )
        }
    }

    /// Configure Twitch with requested ID-token claims and client-secret-post grants.
    pub fn twitch(client_id: &str, client_secret: &str, options: TwitchOptions) -> Self {
        Self {
            kind: ProviderKind::Twitch(options),
            ..Self::custom(
                client_id,
                client_secret,
                "https://id.twitch.tv/oauth2/authorize",
                "https://id.twitch.tv/oauth2/token",
            )
        }
    }

    /// Configure Notion with its user-owned integration and owner profile.
    pub fn notion(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Notion,
            user_info_url: Some("https://api.notion.com/v1/users/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://api.notion.com/v1/oauth/authorize",
                "https://api.notion.com/v1/oauth/token",
            )
        }
    }

    /// Configure Roblox with its profile scopes, account prompt, and HTTP user profile.
    pub fn roblox(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Roblox,
            user_info_url: Some("https://apis.roblox.com/oauth/v1/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://apis.roblox.com/oauth/v1/authorize",
                "https://apis.roblox.com/oauth/v1/token",
            )
        }
    }

    /// Configure TikTok with a client key, comma-separated scopes, and its HTTP profile.
    /// TikTok sends the client key and secret in both token grants.
    pub fn tiktok(client_key: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::TikTok,
            client_key: Some(client_key.into()),
            user_info_url: Some("https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_large_url,display_name,username".into()),
            ..Self::custom(
                "",
                client_secret,
                "https://www.tiktok.com/v2/auth/authorize",
                "https://open.tiktokapis.com/v2/oauth/token/",
            )
        }
    }

    /// Configure Railway with PKCE, HTTP Basic token authentication, and its OpenID profile.
    pub fn railway(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Railway,
            user_info_url: Some("https://backboard.railway.com/oauth/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://backboard.railway.com/oauth/auth",
                "https://backboard.railway.com/oauth/token",
            )
        }
    }

    /// Configure Cloudflare with PKCE and its API user profile.
    /// Pass an empty secret for a public client; confidential clients default to HTTP Basic.
    pub fn cloudflare(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Cloudflare,
            user_info_url: Some("https://api.cloudflare.com/client/v4/user".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://dash.cloudflare.com/oauth2/auth",
                "https://dash.cloudflare.com/oauth2/token",
            )
        }
    }
}
