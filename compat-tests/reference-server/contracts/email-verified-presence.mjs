import { betterAuth } from 'better-auth';
import { genericOAuth } from 'better-auth/plugins/generic-oauth';
import { readFile } from 'node:fs/promises';

const shared = JSON.parse(await readFile(new URL('../../../tests/fixtures/social-http-providers-1.7.6.json', import.meta.url), 'utf8'));
const profiles = {
  discord: { profile: { id: '123456789', email: 'owner@example.test', username: 'Owner', avatar: 'portrait', verified: true }, field: 'verified' },
  huggingface: { profile: shared.providers.huggingface.profile, field: 'email_verified' },
  reddit: { profile: shared.providers.reddit.profile, field: 'has_verified_email' },
  generic: { profile: { id: 'ordinary-generic-account', email: 'owner@example.test', name: 'Owner', emailVerified: true }, field: 'emailVerified' },
};

function field(value, key) {
  return { present: Object.hasOwn(value, key), ...(value[key] === undefined ? {} : { value: value[key] }) };
}

export async function captureEmailVerified() {
  const core = JSON.parse(await readFile(new URL('../node_modules/@better-auth/core/package.json', import.meta.url), 'utf8'));
  const cases = [];
  for (const [id, definition] of Object.entries(profiles)) {
    const inputs = id === 'reddit'
      ? ['unchanged', 'undefined', 'null', 'false', 'true'].map(mapping => ({ raw: 'true', mapping }))
      : [
          ...['true', 'false', 'omitted', 'null'].map(raw => ({ raw, mapping: 'unchanged' })),
          ...['undefined', 'null', 'false', 'true'].map(mapping => ({ raw: 'true', mapping })),
        ];
    for (const input of inputs) {
      const profile = structuredClone(definition.profile);
      if (input.raw === 'omitted') delete profile[definition.field];
      else profile[definition.field] = JSON.parse(input.raw);
      const events = [];
      let mapperInput;
      const mapProfileToUser = async raw => {
        events.push('map');
        mapperInput = field(raw, definition.field);
        if (input.mapping === 'unchanged') return {};
        return { emailVerified: input.mapping === 'undefined' ? undefined : JSON.parse(input.mapping) };
      };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = Object.assign(async () => {
        events.push('http');
        return Response.json(profile);
      }, originalFetch);
      try {
        const options = { clientId: shared.clientId, clientSecret: shared.clientSecret, mapProfileToUser };
        const auth = betterAuth({
          secret: 'ordinary-email-verified-contract-secret-at-least-32-characters',
          baseURL: 'http://email-verified.example.test', logger: { disabled: true }, telemetry: { enabled: false },
          ...(id === 'generic' ? { plugins: [genericOAuth({ config: [{
            providerId: id, ...options,
            authorizationUrl: 'http://email-verified.example.test/authorize',
            tokenUrl: 'http://email-verified.example.test/token',
            getUserInfo: async () => { events.push('custom'); return profile; },
          }] })] } : { socialProviders: { [id]: options } }),
        });
        const context = await auth.$context;
        const provider = context.socialProviders.find(provider => provider.id === id);
        const response = await provider.getUserInfo({ accessToken: 'ordinary-access' });
        const user = JSON.parse(JSON.stringify(response.user));
        cases.push({ provider: id, ...input, expected: {
          user: Object.hasOwn(user, 'emailVerified') ? { emailVerified: user.emailVerified } : {},
          mapperInput, events,
        } });
      } finally { globalThis.fetch = originalFetch; }
    }
  }
  return { version: core.version, profiles, cases };
}

if (import.meta.main) console.log(JSON.stringify(await captureEmailVerified(), null, 2));
