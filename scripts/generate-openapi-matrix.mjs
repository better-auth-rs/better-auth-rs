#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const parseArgs = (argv) => {
  const result = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      throw new Error(`Unknown argument: ${token}`);
    }
    const key = token.slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for --${key}`);
    }
    result[key] = value;
    i += 1;
  }
  return result;
};

const args = parseArgs(process.argv.slice(2));
const profile = args.profile;
const outputPath = args.output ? resolve(args.output) : null;
if (!profile) {
  throw new Error("Missing --profile");
}
if (!outputPath) {
  throw new Error("Missing --output");
}

const { betterAuth } = await import("better-auth/minimal");
const barrel = await import("better-auth/plugins");

// Plugins upstream moved out of the `better-auth/plugins` barrel into their own
// package. `apiKey` left the barrel in better-auth 1.5.0.
const standalonePackages = {
  apiKey: "@better-auth/api-key",
};

const plugins = { ...barrel };
for (const [name, specifier] of Object.entries(standalonePackages)) {
  if (typeof plugins[name] === "function") {
    continue;
  }
  try {
    const mod = await import(specifier);
    if (typeof mod[name] === "function") {
      plugins[name] = mod[name];
    }
  } catch (error) {
    if (error?.code !== "ERR_MODULE_NOT_FOUND") {
      throw error;
    }
  }
}

const loadPasskeyFactory = async () => {
  const candidates = [
    "@better-auth/passkey",
    pathToFileURL(resolve(process.cwd(), "../passkey/dist/index.mjs")).href,
  ];
  for (const specifier of candidates) {
    try {
      const mod = await import(specifier);
      if (typeof mod.passkey === "function") {
        return mod.passkey;
      }
    } catch {
      // try next candidate
    }
  }
  return null;
};

const passkeyFactory = await loadPasskeyFactory();

const pluginSource = (name) =>
  standalonePackages[name]
    ? `better-auth/plugins or ${standalonePackages[name]}`
    : "better-auth/plugins";

const requiredPlugin = (name, ...factoryArgs) => {
  const factory = plugins[name];
  if (typeof factory !== "function") {
    throw new Error(`Plugin '${name}' is not exported by ${pluginSource(name)}`);
  }
  return factory(...factoryArgs);
};

const optionalPlugin = (name, ...factoryArgs) => {
  const factory = plugins[name];
  if (typeof factory !== "function") {
    console.warn(`[warn] plugin '${name}' is unavailable on this ref, skipped`);
    return null;
  }
  return factory(...factoryArgs);
};

const pushIf = (target, plugin) => {
  if (plugin) {
    target.push(plugin);
  }
};

const noopAsync = async () => {};

const profiles = {
  core: () => [requiredPlugin("openAPI")],
  "aligned-rs": () => {
    const selected = [
      requiredPlugin("openAPI"),
      requiredPlugin("apiKey"),
      requiredPlugin("twoFactor"),
      requiredPlugin("organization"),
      requiredPlugin("username"),
    ];
    if (typeof passkeyFactory === "function") {
      selected.push(passkeyFactory());
    } else {
      console.warn("[warn] plugin 'passkey' is unavailable on this ref, skipped");
    }
    return selected;
  },
  "all-in": () => {
    const selected = [requiredPlugin("openAPI")];

    pushIf(selected, optionalPlugin("admin"));
    pushIf(selected, optionalPlugin("anonymous"));
    pushIf(selected, optionalPlugin("apiKey"));
    pushIf(selected, optionalPlugin("bearer"));
    pushIf(
      selected,
      optionalPlugin("captcha", {
        provider: "cloudflare-turnstile",
        secretKey: "dummy-captcha-secret",
      }),
    );
    pushIf(
      selected,
      optionalPlugin(
        "customSession",
        async ({ user, session }) => ({ user, session }),
      ),
    );
    pushIf(selected, optionalPlugin("deviceAuthorization"));
    pushIf(
      selected,
      optionalPlugin("emailOTP", {
        sendVerificationOTP: noopAsync,
      }),
    );
    pushIf(
      selected,
      optionalPlugin("genericOAuth", {
        config: [
          {
            providerId: "dummy-oauth",
            clientId: "dummy-client-id",
            clientSecret: "dummy-client-secret",
            authorizationUrl: "https://example.com/oauth/authorize",
            tokenUrl: "https://example.com/oauth/token",
            userInfoUrl: "https://example.com/oauth/userinfo",
            scopes: ["openid", "profile", "email"],
          },
        ],
      }),
    );
    pushIf(selected, optionalPlugin("haveIBeenPwned"));
    pushIf(selected, optionalPlugin("jwt"));
    pushIf(selected, optionalPlugin("lastLoginMethod"));
    pushIf(
      selected,
      optionalPlugin("magicLink", {
        sendMagicLink: noopAsync,
      }),
    );
    pushIf(selected, optionalPlugin("multiSession"));
    pushIf(selected, optionalPlugin("oAuthProxy"));
    const oidcProviderPlugin = optionalPlugin("oidcProvider", {
      loginPage: "/login",
    });
    if (oidcProviderPlugin) {
      pushIf(selected, oidcProviderPlugin);
    } else {
      pushIf(
        selected,
        optionalPlugin("mcp", {
          loginPage: "/login",
        }),
      );
    }
    pushIf(
      selected,
      optionalPlugin("oneTap", {
        clientId: "dummy-client-id",
      }),
    );
    pushIf(selected, optionalPlugin("oneTimeToken"));
    pushIf(selected, optionalPlugin("organization"));
    pushIf(selected, optionalPlugin("phoneNumber"));
    pushIf(
      selected,
      optionalPlugin("siwe", {
        domain: "localhost",
        getNonce: async () => "dummy-nonce",
        verifyMessage: async () => true,
      }),
    );
    pushIf(selected, optionalPlugin("twoFactor"));
    pushIf(selected, optionalPlugin("username"));

    if (typeof passkeyFactory === "function") {
      selected.push(passkeyFactory());
    } else {
      console.warn("[warn] plugin 'passkey' is unavailable on this ref, skipped");
    }

    return selected;
  },
};

const buildPlugins = profiles[profile];
if (typeof buildPlugins !== "function") {
  throw new Error(
    `Unsupported profile '${profile}'. Allowed: ${Object.keys(profiles).join(", ")}`,
  );
}

const auth = betterAuth({
  secret: "better-auth-rs-openapi-alignment-script-secret-32-bytes",
  baseURL: "http://localhost:3000",
  trustedOrigins: ["http://localhost:3000"],
  emailAndPassword: {
    enabled: true,
  },
  socialProviders: {},
  plugins: buildPlugins(),
});

if (!auth.api || typeof auth.api.generateOpenAPISchema !== "function") {
  throw new Error("generateOpenAPISchema is not available. Ensure openAPI() is enabled.");
}

const schema = await auth.api.generateOpenAPISchema();
await writeFile(outputPath, JSON.stringify(schema, null, 2), "utf8");
console.log(`[ok] ${profile} -> ${outputPath}`);
