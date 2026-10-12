use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, LitStr, Type};

struct FieldInfo {
    ident: Ident,
    ty: Type,
    default_expr: TokenStream,
    skip: bool,
}

pub(crate) fn derive_plugin_config(input: &DeriveInput) -> TokenStream {
    let (plugin_name, constructor) = match parse_plugin_options(input) {
        Ok(options) => options,
        Err(error) => return error.to_compile_error(),
    };
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
        .map(|field| gen_builder_method(field, constructor.is_some()))
        .collect();

    let initialize = match &constructor {
        Some(constructor) => quote! { Self::#constructor(config) },
        None => quote! { Self { config } },
    };
    let plugin_impl = quote! {
        impl #plugin_name {
            pub fn new() -> Self {
                Self::with_config(#config_name::default())
            }

            pub fn with_config(config: #config_name) -> Self {
                #initialize
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

fn parse_plugin_options(input: &DeriveInput) -> Result<(Ident, Option<Ident>), syn::Error> {
    let mut name = None;
    let mut constructor = None;
    for attr in &input.attrs {
        if attr.path().is_ident("plugin") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    let value: LitStr = meta.value()?.parse()?;
                    name = Some(Ident::new(&value.value(), value.span()));
                    Ok(())
                } else if meta.path.is_ident("constructor") {
                    constructor = Some(meta.value()?.parse()?);
                    Ok(())
                } else {
                    Err(meta.error("expected `name` or `constructor`"))
                }
            })?;
        }
    }
    let name = name.ok_or_else(|| {
        syn::Error::new_spanned(input, "missing #[plugin(name = \"...\")] attribute")
    })?;
    Ok((name, constructor))
}

#[expect(
    clippy::unwrap_used,
    reason = "proc-macro error reporting: named fields always have idents"
)]
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
        if segment.ident == "Option"
            && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
            && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
        {
            return Some(inner);
        }
    }
    None
}

fn gen_builder_method(fi: &FieldInfo, reconfigure: bool) -> TokenStream {
    let field_name = &fi.ident;
    let ty = &fi.ty;
    let finish = if reconfigure {
        quote! { Self::with_config(self.config) }
    } else {
        quote! { self }
    };

    if is_string_type(ty) {
        quote! {
            pub fn #field_name(mut self, val: impl Into<String>) -> Self {
                self.config.#field_name = val.into();
                #finish
            }
        }
    } else if let Some(inner) = extract_option_inner(ty) {
        quote! {
            pub fn #field_name(mut self, val: #inner) -> Self {
                self.config.#field_name = Some(val);
                #finish
            }
        }
    } else {
        quote! {
            pub fn #field_name(mut self, val: #ty) -> Self {
                self.config.#field_name = val;
                #finish
            }
        }
    }
}
