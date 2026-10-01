use super::ErrorPageCustomization;

pub(super) fn valid_error_code(input: &str) -> bool {
    !input.is_empty()
        && input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '\'')
}

fn is_preserved_entity(input: &str) -> bool {
    input.starts_with("amp;")
        || input.starts_with("lt;")
        || input.starts_with("gt;")
        || input.starts_with("quot;")
        || input.starts_with("#39;")
        || input.strip_prefix("#x").is_some_and(|hex| {
            let Some((hex, _)) = hex.split_once(';') else {
                return false;
            };
            !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
        })
        || input.strip_prefix('#').is_some_and(|digits| {
            let Some((digits, _)) = digits.split_once(';') else {
                return false;
            };
            !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
        })
}

fn sanitize_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());

    for (idx, ch) in input.char_indices() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '&' => {
                let rest = &input[idx + ch.len_utf8()..];
                if is_preserved_entity(rest) {
                    out.push('&');
                } else {
                    out.push_str("&amp;");
                }
            }
            _ => out.push(ch),
        }
    }

    out
}

fn default_error_description(code: &str) -> String {
    format!(
        "We encountered an unexpected error. Please try again or return to the home page. If you're a developer, you can find <a href='https://better-auth.com/docs/reference/errors/{code}' target='_blank' rel=\"noopener noreferrer\" style='color: var(--foreground); text-decoration: underline;'>more information about the error</a>."
    )
}

/// Build the default HTML error page.
pub fn error_page_html(code: &str) -> String {
    error_page_html_with_description(code, None)
}

/// Build the default HTML error page with an escaped description.
pub fn error_page_html_with_description(code: &str, description: Option<&str>) -> String {
    render(code, description, None)
}

fn text<'a>(value: &'a Option<String>, default: &'a str) -> &'a str {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(default)
}

pub(super) fn render(
    code: &str,
    description: Option<&str>,
    custom: Option<&ErrorPageCustomization>,
) -> String {
    let defaults = ErrorPageCustomization::default();
    let custom = custom.unwrap_or(&defaults);
    let safe_code = if valid_error_code(code) {
        code
    } else {
        "UNKNOWN"
    };
    let description = description
        .filter(|value| !value.is_empty())
        .map(sanitize_html)
        .unwrap_or_else(|| default_error_description(safe_code));
    let ask_ai_query = format!("What%20does%20the%20error%20code%20{safe_code}%20mean%3F");
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Error</title>
    <style>
      * {{
        box-sizing: border-box;
      }}
      body {{
        font-family: {v7};
        background: {v8};
        color: var(--foreground);
        margin: 0;
      }}
      :root,
      :host {{
        --spacing: 0.25rem;
        --container-md: 28rem;
        --text-sm: {v9};
        --text-sm--line-height: calc(1.25 / 0.875);
        --text-2xl: {v10};
        --text-2xl--line-height: calc(2 / 1.5);
        --text-4xl: {v11};
        --text-4xl--line-height: calc(2.5 / 2.25);
        --text-6xl: {v12};
        --text-6xl--line-height: 1;
        --font-weight-medium: 500;
        --font-weight-semibold: 600;
        --font-weight-bold: 700;
        --default-transition-duration: 150ms;
        --default-transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);
        --radius: {v13};
        --default-mono-font-family: {v14};
        --primary: {v15};
        --primary-foreground: {v16};
        --background: {v17};
        --foreground: {v18};
        --border: {v19};
        --destructive: {v20};
        --muted-foreground: {v21};
        --corner-border: {v22};
      }}

      button, .btn {{
        cursor: pointer;
        background: none;
        border: none;
        color: inherit;
        font: inherit;
        transition: all var(--default-transition-duration)
          var(--default-transition-timing-function);
      }}
      button:hover, .btn:hover {{
        opacity: 0.8;
      }}

      @media (prefers-color-scheme: dark) {{
        :root,
        :host {{
          --primary: {v23};
          --primary-foreground: {v24};
          --background: {v25};
          --foreground: {v26};
          --border: {v27};
          --destructive: {v28};
          --muted-foreground: {v29};
          --corner-border: {v30};
        }}
      }}
      @media (max-width: 640px) {{
        :root, :host {{
          --text-6xl: 2.5rem;
          --text-2xl: 1.25rem;
          --text-sm: 0.8125rem;
        }}
      }}
      @media (max-width: 480px) {{
        :root, :host {{
          --text-6xl: 2rem;
          --text-2xl: 1.125rem;
        }}
      }}
    </style>
  </head>
  <body style="width: 100vw; min-height: 100vh; overflow-x: hidden; overflow-y: auto;">
    <div
        style="
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 1.5rem;
            position: relative;
            width: 100%;
            min-height: 100vh;
            padding: 1rem;
        "
        >
{v0}

<div
  style="
    position: relative;
    z-index: 10;
    border: 2px solid var(--border);
    background: {v31};
    padding: 1.5rem;
    max-width: 42rem;
    width: 100%;
  "
>
    {v1}

        <div style="text-align: center; margin-bottom: 1.5rem;">
          <div style="margin-bottom: 1.5rem;">
            <div
              style="
                display: inline-block;
                border: 2px solid {v6};
                padding: 0.375rem 1rem;
              "
            >
              <h1
                style="
                  font-size: var(--text-6xl);
                  font-weight: var(--font-weight-semibold);
                  color: {v32};
                  letter-spacing: -0.02em;
                  margin: 0;
                "
              >
                ERROR
              </h1>
            </div>
            <div
              style="
                height: 2px;
                background-color: var(--border);
                width: calc(100% + 3rem);
                margin-left: -1.5rem;
                margin-top: 1.5rem;
              "
            ></div>
          </div>

          <h2
            style="
              font-size: var(--text-2xl);
              font-weight: var(--font-weight-semibold);
              color: var(--foreground);
              margin: 0 0 1rem;
            "
          >
            Something went wrong
          </h2>

          <div
            style="
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                border: 2px solid var(--border);
                background-color: var(--muted);
                padding: 0.375rem 0.75rem;
                margin: 0 0 1rem;
                flex-wrap: wrap;
                justify-content: center;
            "
            >
            <span
                style="
                font-size: 0.75rem;
                color: var(--muted-foreground);
                font-weight: var(--font-weight-semibold);
                "
            >
                CODE:
            </span>
            <span
                style="
                font-size: var(--text-sm);
                font-family: var(--default-mono-font-family, monospace);
                color: var(--foreground);
                word-break: break-all;
                "
            >
                {v5}
            </span>
            </div>

          <p
            style="
              color: var(--muted-foreground);
              max-width: 28rem;
              margin: 0 auto;
              font-size: var(--text-sm);
              line-height: 1.5;
              text-wrap: pretty;
            "
          >
            {v2}
          </p>
        </div>

        <div
          style="
            display: flex;
            gap: 0.75rem;
            margin-top: 1.5rem;
            justify-content: center;
            flex-wrap: wrap;
          "
        >
          <a
            href="/"
            style="
              text-decoration: none;
            "
          >
            <div
              style="
                border: 2px solid var(--border);
                background: var(--primary);
                color: var(--primary-foreground);
                padding: 0.5rem 1rem;
                border-radius: 0;
                white-space: nowrap;
              "
              class="btn"
            >
              Go Home
            </div>
          </a>
          <a
            href="https://better-auth.com/docs/reference/errors/{v4}?askai={v3}"
            target="_blank"
            rel="noopener noreferrer"
            style="
              text-decoration: none;
            "
          >
            <div
              style="
                border: 2px solid var(--border);
                background: transparent;
                color: var(--foreground);
                padding: 0.5rem 1rem;
                border-radius: 0;
                white-space: nowrap;
              "
              class="btn"
            >
              Ask AI
            </div>
          </a>
        </div>
      </div>
    </div>
  </body>
</html>"##,
        v0 = if custom.disable_background_grid {
            String::new()
        } else {
            format!(
                r##"
      <div
        style="
          position: absolute;
          inset: 0;
          background-image: linear-gradient(to right, {v4} 1px, transparent 1px),
            linear-gradient(to bottom, {v5} 1px, transparent 1px);
          background-size: 40px 40px;
          opacity: 0.6;
          pointer-events: none;
          width: 100vw;
          height: 100vh;
        "
      ></div>
      <div
        style="
          position: absolute;
          inset: 0;
          display: flex;
          align-items: center;
          justify-content: center;
          background: {v6};
          mask-image: radial-gradient(ellipse at center, transparent 20%, black);
          -webkit-mask-image: radial-gradient(ellipse at center, transparent 20%, black);
          pointer-events: none;
        "
      ></div>
"##,
                v4 = text(&custom.colors.grid_color, "var(--border)"),
                v5 = text(&custom.colors.grid_color, "var(--border)"),
                v6 = text(&custom.colors.background, "var(--background)")
            )
        },
        v1 = if custom.disable_corner_decorations {
            String::new()
        } else {
            format!(
                r##"
        <!-- Corner decorations -->
        <div
          style="
            position: absolute;
            top: -2px;
            left: -2px;
            width: 2rem;
            height: 2rem;
            border-top: 4px solid var(--corner-border);
            border-left: 4px solid var(--corner-border);
          "
        ></div>
        <div
          style="
            position: absolute;
            top: -2px;
            right: -2px;
            width: 2rem;
            height: 2rem;
            border-top: 4px solid var(--corner-border);
            border-right: 4px solid var(--corner-border);
          "
        ></div>
{gap}
        <div
          style="
            position: absolute;
            bottom: -2px;
            left: -2px;
            width: 2rem;
            height: 2rem;
            border-bottom: 4px solid var(--corner-border);
            border-left: 4px solid var(--corner-border);
          "
        ></div>
        <div
          style="
            position: absolute;
            bottom: -2px;
            right: -2px;
            width: 2rem;
            height: 2rem;
            border-bottom: 4px solid var(--corner-border);
            border-right: 4px solid var(--corner-border);
          "
        ></div>"##,
                gap = "  "
            )
        },
        v2 = description,
        v3 = ask_ai_query,
        v4 = safe_code,
        v5 = sanitize_html(safe_code),
        v6 = if custom.disable_title_border {
            "transparent"
        } else {
            text(&custom.colors.title_border, "var(--destructive)")
        },
        v7 = text(
            &custom.font.default_family,
            "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
        ),
        v8 = text(&custom.colors.background, "var(--background)"),
        v9 = text(&custom.size.text_sm, "0.875rem"),
        v10 = text(&custom.size.text2xl, "1.5rem"),
        v11 = text(&custom.size.text4xl, "2.25rem"),
        v12 = text(&custom.size.text6xl, "3rem"),
        v13 = text(&custom.size.radius_sm, "0.625rem"),
        v14 = text(&custom.font.mono_family, "var(--font-geist-mono)"),
        v15 = text(&custom.colors.primary, "black"),
        v16 = text(&custom.colors.primary_foreground, "white"),
        v17 = text(&custom.colors.background, "white"),
        v18 = text(&custom.colors.foreground, "oklch(0.271 0 0)"),
        v19 = text(&custom.colors.border, "oklch(0.89 0 0)"),
        v20 = text(&custom.colors.destructive, "oklch(0.55 0.15 25.723)"),
        v21 = text(&custom.colors.muted_foreground, "oklch(0.545 0 0)"),
        v22 = text(&custom.colors.corner_border, "#404040"),
        v23 = text(&custom.colors.primary, "white"),
        v24 = text(&custom.colors.primary_foreground, "black"),
        v25 = text(&custom.colors.background, "oklch(0.15 0 0)"),
        v26 = text(&custom.colors.foreground, "oklch(0.98 0 0)"),
        v27 = text(&custom.colors.border, "oklch(0.27 0 0)"),
        v28 = text(&custom.colors.destructive, "oklch(0.65 0.15 25.723)"),
        v29 = text(&custom.colors.muted_foreground, "oklch(0.65 0 0)"),
        v30 = text(&custom.colors.corner_border, "#a0a0a0"),
        v31 = text(&custom.colors.card_background, "var(--background)"),
        v32 = text(&custom.colors.title_color, "var(--foreground)")
    )
}
