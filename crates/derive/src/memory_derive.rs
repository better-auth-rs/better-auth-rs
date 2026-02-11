use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::DeriveInput;

use crate::helpers::{FieldInfo, find_field_for_getter, parse_named_fields};

/// How a struct field is initialised inside `from_create`.
#[derive(Clone, Copy)]
pub(crate) enum CreateInit {
    IdParam,
    TokenParam,
    NowParam,
    CloneCreate(&'static str),
    CopyCreate(&'static str),
    UnwrapBoolCreate(&'static str),
    UnwrapDefaultCreate(&'static str),
    StaticBool(bool),
    StaticNone,
    InvitationPending,
}

/// How an update field is applied to the struct.
#[derive(Clone, Copy)]
pub(crate) enum UpdateApply {
    /// `if let Some(v) = &update.f { self.f = Some(v.clone()); }`
    CloneIntoOption,
    /// `if let Some(v) = update.f { self.f = v; }`
    CopyDirect,
    /// `if let Some(v) = update.f { self.f = Some(v); }`
    CopyIntoOption,
    /// `if let Some(v) = &update.f { self.f = v.clone(); }`
    CloneDirect,
}

/// Setter methods that some Memory* traits require.
#[derive(Clone, Copy)]
pub(crate) enum SetterDef {
    /// `fn set_expires_at(&mut self, at: DateTime<Utc>)` — field "expires_at"
    ExpiresAt,
    /// `fn set_active_organization_id(&mut self, org_id: Option<String>)` — field "active_organization_id"
    ActiveOrganizationId,
    /// `fn set_updated_at(&mut self, at: DateTime<Utc>)` — field "updated_at"
    UpdatedAt,
    /// `fn set_role(&mut self, role: String)` — field "role"
    Role,
    /// `fn set_status(&mut self, status: InvitationStatus)` — field "status"
    Status,
}

use CreateInit::*;
use UpdateApply::*;

fn mk_ident(s: &str) -> syn::Ident {
    syn::Ident::new(s, proc_macro2::Span::call_site())
}

fn gen_create_init_expr(init: &CreateInit) -> TokenStream2 {
    match init {
        IdParam => quote! { id },
        TokenParam => quote! { token },
        NowParam => quote! { now },
        CloneCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field.clone() }
        }
        CopyCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field }
        }
        UnwrapBoolCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field.unwrap_or(false) }
        }
        UnwrapDefaultCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field.clone().unwrap_or_default() }
        }
        StaticBool(b) => quote! { #b },
        StaticNone => quote! { ::core::option::Option::None },
        InvitationPending => {
            quote! { ::better_auth_core::types::InvitationStatus::Pending }
        }
    }
}

/// Build the `Self { field: expr, ... }` body for `from_create`.
fn gen_from_create_body(
    field_infos: &[FieldInfo],
    create_mappings: &[(&str, CreateInit)],
) -> TokenStream2 {
    let field_inits: Vec<TokenStream2> = field_infos
        .iter()
        .map(|info| {
            let field_ident = &info.ident;
            let ident_str = info.ident.to_string();
            let getter_name = info.auth_field_name.as_deref().unwrap_or(&ident_str);

            let init_expr = create_mappings
                .iter()
                .find(|(name, _)| *name == getter_name)
                .map(|(_, init)| gen_create_init_expr(init))
                .unwrap_or_else(|| {
                    if let Some(ref expr) = info.auth_default {
                        expr.clone()
                    } else {
                        quote! { ::core::default::Default::default() }
                    }
                });

            quote! { #field_ident: #init_expr }
        })
        .collect();

    quote! { Self { #(#field_inits),* } }
}

fn gen_update_apply_stmt(
    struct_field: &syn::Ident,
    update_field: &syn::Ident,
    apply: UpdateApply,
) -> TokenStream2 {
    match apply {
        UpdateApply::CloneIntoOption => quote! {
            if let ::core::option::Option::Some(ref v) = update.#update_field {
                self.#struct_field = ::core::option::Option::Some(v.clone());
            }
        },
        UpdateApply::CopyDirect => quote! {
            if let ::core::option::Option::Some(v) = update.#update_field {
                self.#struct_field = v;
            }
        },
        UpdateApply::CopyIntoOption => quote! {
            if let ::core::option::Option::Some(v) = update.#update_field {
                self.#struct_field = ::core::option::Option::Some(v);
            }
        },
        UpdateApply::CloneDirect => quote! {
            if let ::core::option::Option::Some(ref v) = update.#update_field {
                self.#struct_field = v.clone();
            }
        },
    }
}

/// Build the body of `apply_update`, including the final `updated_at = now()`.
fn gen_apply_update_body(
    field_infos: &[FieldInfo],
    update_mappings: &[(&str, &str, UpdateApply)],
) -> TokenStream2 {
    let mut stmts = Vec::new();

    for &(update_field_name, getter_name, apply) in update_mappings {
        if let Some(struct_field) = find_field_for_getter(field_infos, getter_name) {
            let update_ident = mk_ident(update_field_name);
            stmts.push(gen_update_apply_stmt(struct_field, &update_ident, apply));
        }
    }

    // Always set updated_at at the end
    if let Some(field) = find_field_for_getter(field_infos, "updated_at") {
        stmts.push(quote! { self.#field = ::chrono::Utc::now(); });
    }

    quote! { #(#stmts)* }
}

/// Generate setter method implementations from SetterDef descriptors.
fn gen_setter_methods(field_infos: &[FieldInfo], setters: &[SetterDef]) -> TokenStream2 {
    let mut methods = Vec::new();
    for setter in setters {
        match setter {
            SetterDef::ExpiresAt => {
                if let Some(f) = find_field_for_getter(field_infos, "expires_at") {
                    methods.push(quote! {
                        fn set_expires_at(&mut self, at: ::chrono::DateTime<::chrono::Utc>) {
                            self.#f = at;
                        }
                    });
                }
            }
            SetterDef::ActiveOrganizationId => {
                if let Some(f) = find_field_for_getter(field_infos, "active_organization_id") {
                    methods.push(quote! {
                        fn set_active_organization_id(
                            &mut self,
                            org_id: ::core::option::Option<::std::string::String>,
                        ) {
                            self.#f = org_id;
                        }
                    });
                }
            }
            SetterDef::UpdatedAt => {
                if let Some(f) = find_field_for_getter(field_infos, "updated_at") {
                    methods.push(quote! {
                        fn set_updated_at(&mut self, at: ::chrono::DateTime<::chrono::Utc>) {
                            self.#f = at;
                        }
                    });
                }
            }
            SetterDef::Role => {
                if let Some(f) = find_field_for_getter(field_infos, "role") {
                    methods.push(quote! {
                        fn set_role(&mut self, role: ::std::string::String) {
                            self.#f = role;
                        }
                    });
                }
            }
            SetterDef::Status => {
                if let Some(f) = find_field_for_getter(field_infos, "status") {
                    methods.push(quote! {
                        fn set_status(&mut self, status: ::better_auth_core::types::InvitationStatus) {
                            self.#f = status;
                        }
                    });
                }
            }
        }
    }
    quote! { #(#methods)* }
}

/// Configuration for a Memory* trait derive macro. Each Memory* macro
/// is fully described by one of these — the shared `derive_memory_trait`
/// function does all the code generation.
pub(crate) struct MemoryTraitDef {
    pub trait_name: &'static str,
    pub create_type: &'static str,
    pub has_token_param: bool,
    pub create_mappings: &'static [(&'static str, CreateInit)],
    pub update_type: Option<&'static str>,
    pub update_mappings: &'static [(&'static str, &'static str, UpdateApply)],
    pub setters: &'static [SetterDef],
}

/// Shared code generation for all Memory* traits.
pub(crate) fn derive_memory_trait(input: &DeriveInput, def: &MemoryTraitDef) -> TokenStream2 {
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let field_infos = match parse_named_fields(input, def.trait_name) {
        Ok(fi) => fi,
        Err(err) => return err,
    };

    let create_body = gen_from_create_body(&field_infos, def.create_mappings);
    let trait_ident = mk_ident(def.trait_name);
    let create_type_ident = mk_ident(def.create_type);

    let from_create_fn = if def.has_token_param {
        quote! {
            fn from_create(
                id: ::std::string::String,
                token: ::std::string::String,
                create: &::better_auth_core::types::#create_type_ident,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }
        }
    } else {
        quote! {
            fn from_create(
                id: ::std::string::String,
                create: &::better_auth_core::types::#create_type_ident,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }
        }
    };

    let update_fn = if let Some(update_type_name) = def.update_type {
        let update_type_ident = mk_ident(update_type_name);
        let update_body = gen_apply_update_body(&field_infos, def.update_mappings);
        quote! {
            fn apply_update(&mut self, update: &::better_auth_core::types::#update_type_ident) {
                #update_body
            }
        }
    } else {
        quote! {}
    };

    let setter_fns = gen_setter_methods(&field_infos, def.setters);

    quote! {
        impl #impl_generics ::better_auth_core::adapters::memory::#trait_ident
            for #struct_name #ty_generics #where_clause
        {
            #from_create_fn
            #update_fn
            #setter_fns
        }
    }
}

pub(crate) const MEMORY_USER_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryUser",
    create_type: "CreateUser",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("email", CloneCreate("email")),
        ("name", CloneCreate("name")),
        ("email_verified", UnwrapBoolCreate("email_verified")),
        ("image", CloneCreate("image")),
        ("created_at", NowParam),
        ("updated_at", NowParam),
        ("username", CloneCreate("username")),
        ("display_username", CloneCreate("display_username")),
        ("two_factor_enabled", StaticBool(false)),
        ("role", CloneCreate("role")),
        ("banned", StaticBool(false)),
        ("ban_reason", StaticNone),
        ("ban_expires", StaticNone),
        ("metadata", UnwrapDefaultCreate("metadata")),
    ],
    update_type: Some("UpdateUser"),
    update_mappings: &[
        ("email", "email", CloneIntoOption),
        ("name", "name", CloneIntoOption),
        ("image", "image", CloneIntoOption),
        ("email_verified", "email_verified", CopyDirect),
        ("username", "username", CloneIntoOption),
        ("display_username", "display_username", CloneIntoOption),
        ("role", "role", CloneIntoOption),
        ("banned", "banned", CopyDirect),
        ("ban_reason", "ban_reason", CloneIntoOption),
        ("ban_expires", "ban_expires", CopyIntoOption),
        ("two_factor_enabled", "two_factor_enabled", CopyDirect),
        ("metadata", "metadata", CloneDirect),
    ],
    setters: &[],
};

pub(crate) const MEMORY_SESSION_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemorySession",
    create_type: "CreateSession",
    has_token_param: true,
    create_mappings: &[
        ("id", IdParam),
        ("token", TokenParam),
        ("expires_at", CopyCreate("expires_at")),
        ("created_at", NowParam),
        ("updated_at", NowParam),
        ("ip_address", CloneCreate("ip_address")),
        ("user_agent", CloneCreate("user_agent")),
        ("user_id", CloneCreate("user_id")),
        ("impersonated_by", CloneCreate("impersonated_by")),
        (
            "active_organization_id",
            CloneCreate("active_organization_id"),
        ),
        ("active", StaticBool(true)),
    ],
    update_type: None,
    update_mappings: &[],
    setters: &[
        SetterDef::ExpiresAt,
        SetterDef::ActiveOrganizationId,
        SetterDef::UpdatedAt,
    ],
};

pub(crate) const MEMORY_ACCOUNT_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryAccount",
    create_type: "CreateAccount",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("account_id", CloneCreate("account_id")),
        ("provider_id", CloneCreate("provider_id")),
        ("user_id", CloneCreate("user_id")),
        ("access_token", CloneCreate("access_token")),
        ("refresh_token", CloneCreate("refresh_token")),
        ("id_token", CloneCreate("id_token")),
        (
            "access_token_expires_at",
            CopyCreate("access_token_expires_at"),
        ),
        (
            "refresh_token_expires_at",
            CopyCreate("refresh_token_expires_at"),
        ),
        ("scope", CloneCreate("scope")),
        ("password", CloneCreate("password")),
        ("created_at", NowParam),
        ("updated_at", NowParam),
    ],
    update_type: None,
    update_mappings: &[],
    setters: &[],
};

pub(crate) const MEMORY_ORGANIZATION_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryOrganization",
    create_type: "CreateOrganization",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("name", CloneCreate("name")),
        ("slug", CloneCreate("slug")),
        ("logo", CloneCreate("logo")),
        ("metadata", CloneCreate("metadata")),
        ("created_at", NowParam),
        ("updated_at", NowParam),
    ],
    update_type: Some("UpdateOrganization"),
    update_mappings: &[
        ("name", "name", CloneDirect),
        ("slug", "slug", CloneDirect),
        ("logo", "logo", CloneIntoOption),
        ("metadata", "metadata", CloneIntoOption),
    ],
    setters: &[],
};

pub(crate) const MEMORY_MEMBER_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryMember",
    create_type: "CreateMember",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("organization_id", CloneCreate("organization_id")),
        ("user_id", CloneCreate("user_id")),
        ("role", CloneCreate("role")),
        ("created_at", NowParam),
    ],
    update_type: None,
    update_mappings: &[],
    setters: &[SetterDef::Role],
};

pub(crate) const MEMORY_INVITATION_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryInvitation",
    create_type: "CreateInvitation",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("organization_id", CloneCreate("organization_id")),
        ("email", CloneCreate("email")),
        ("role", CloneCreate("role")),
        ("status", InvitationPending),
        ("inviter_id", CloneCreate("inviter_id")),
        ("expires_at", CopyCreate("expires_at")),
        ("created_at", NowParam),
    ],
    update_type: None,
    update_mappings: &[],
    setters: &[SetterDef::Status],
};

pub(crate) const MEMORY_VERIFICATION_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryVerification",
    create_type: "CreateVerification",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("identifier", CloneCreate("identifier")),
        ("value", CloneCreate("value")),
        ("expires_at", CopyCreate("expires_at")),
        ("created_at", NowParam),
        ("updated_at", NowParam),
    ],
    update_type: None,
    update_mappings: &[],
    setters: &[],
};
