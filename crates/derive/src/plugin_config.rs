use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, LitStr, Type};

struct FieldInfo {
    ident: Ident,
    ty: Type,
    default_expr: TokenStream,
    skip: bool,
}

pub fn derive_plugin_config(input: &DeriveInput) -> TokenStream {
    let plugin_name = parse_plugin_name(input);
    let config_name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return syn::Error::new_spanned(
                    &input.ident,
                    "PluginConfig requires a struct with named fields",
                )
                .to_compile_error();
            }
        },
        _ => {
            return syn::Error::new_spanned(&input.ident, "PluginConfig requires a struct")
                .to_compile_error();
        }
    };

    let field_infos: Vec<FieldInfo> = match fields.iter().map(parse_field_info).collect() {
        Ok(v) => v,
        Err(e) => return e.to_compile_error(),
    };

    // Generate Default impl for Config
    let default_fields: Vec<_> = field_infos
        .iter()
        .map(|fi| {
            let name = &fi.ident;
            let expr = &fi.default_expr;
            quote! { #name: #expr }
        })
        .collect();

    let default_impl = quote! {
        impl Default for #config_name {
            fn default() -> Self {
                Self {
                    #(#default_fields,)*
                }
            }
        }
    };

    // Generate builder methods
    let builder_methods: Vec<_> = field_infos
        .iter()
        .filter(|fi| !fi.skip)
        .map(gen_builder_method)
        .collect();

    let plugin_impl = quote! {
        impl #plugin_name {
            pub fn new() -> Self {
                Self {
                    config: #config_name::default(),
                }
            }

            pub fn with_config(config: #config_name) -> Self {
                Self { config }
            }

            #(#builder_methods)*
        }
    };

    let plugin_default = quote! {
        impl Default for #plugin_name {
            fn default() -> Self {
                Self::new()
            }
        }
    };

    quote! {
        #default_impl
        #plugin_impl
        #plugin_default
    }
}

fn parse_plugin_name(input: &DeriveInput) -> Ident {
    for attr in &input.attrs {
        if attr.path().is_ident("plugin") {
            let name: LitStr = attr
                .parse_args_with(|stream: syn::parse::ParseStream| {
                    let ident: Ident = stream.parse()?;
                    if ident != "name" {
                        return Err(syn::Error::new(ident.span(), "expected `name`"));
                    }
                    let _: syn::Token![=] = stream.parse()?;
                    stream.parse::<LitStr>()
                })
                .expect("expected #[plugin(name = \"...\")]");
            return Ident::new(&name.value(), name.span());
        }
    }
    panic!("missing #[plugin(name = \"...\")] attribute");
}

fn parse_field_info(field: &syn::Field) -> Result<FieldInfo, syn::Error> {
    let ident = field.ident.clone().unwrap();
    let ty = field.ty.clone();
    let mut default_expr = None;
    let mut skip = false;

    for attr in &field.attrs {
        if attr.path().is_ident("config") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("skip") {
                    skip = true;
                    Ok(())
                } else if meta.path.is_ident("default") {
                    let value = meta.value()?;
                    let expr: syn::Expr = value.parse()?;
                    default_expr = Some(quote!(#expr));
                    Ok(())
                } else {
                    Err(meta.error("expected `skip` or `default`"))
                }
            })?;
        }
    }

    let default_expr = default_expr.ok_or_else(|| {
        syn::Error::new_spanned(
            &ident,
            format!("field `{ident}` requires #[config(default = ...)]"),
        )
    })?;

    Ok(FieldInfo {
        ident,
        ty,
        default_expr,
        skip,
    })
}

fn is_string_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        type_path.path.is_ident("String")
    } else {
        false
    }
}

fn extract_option_inner(ty: &Type) -> Option<&Type> {
    if let Type::Path(type_path) = ty {
        let segment = type_path.path.segments.last()?;
        if segment.ident == "Option" {
            if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                    return Some(inner);
                }
            }
        }
    }
    None
}

fn gen_builder_method(fi: &FieldInfo) -> TokenStream {
    let field_name = &fi.ident;
    let ty = &fi.ty;

    if is_string_type(ty) {
        quote! {
            pub fn #field_name(mut self, val: impl Into<String>) -> Self {
                self.config.#field_name = val.into();
                self
            }
        }
    } else if let Some(inner) = extract_option_inner(ty) {
        quote! {
            pub fn #field_name(mut self, val: #inner) -> Self {
                self.config.#field_name = Some(val);
                self
            }
        }
    } else {
        quote! {
            pub fn #field_name(mut self, val: #ty) -> Self {
                self.config.#field_name = val;
                self
            }
        }
    }
}
