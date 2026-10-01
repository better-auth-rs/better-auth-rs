import { expect } from "bun:test";

type Invoke = (input: Record<string, unknown>) => Promise<any>;
type Register = (name: string, scenario: (invoke: Invoke) => Promise<unknown>) => void;

export function registerApiErrorContracts(register: Register, production: boolean) {
  register("production redirects by default while explicit customization renders HTML", async invoke => {
    const query = `?${new URLSearchParams({ error: "<script>", error_description: "<img src=x>" })}`;
    const defaults = await invoke({ page: true, query, needles: ["UNKNOWN", "&lt;img src=x&gt;"] });
    expect(defaults.output.status).toBe(production ? 302 : 200);
    if (production) expect(defaults.output.location).toBe(`/?${new URLSearchParams({ error: "UNKNOWN", error_description: "<img src=x>" })}`);
    else expect(defaults.output.matches).toEqual([true, true]);
    const custom = await invoke({ page: true, query, customize: {}, needles: ["UNKNOWN", "&lt;img src=x&gt;"] });
    expect(custom.output.status).toBe(200); expect(custom.output.matches).toEqual([true, true]);
    return { defaults, custom };
  });

  register("OAuth uses errorURL as its default destination without redirecting unrelated failures", async invoke => {
    const oauth = await invoke({ oauth: true, query: "?error=access_denied", errorURL: "/failure?existing=1#part" });
    expect(oauth.output.status).toBe(302); expect(oauth.output.location).toBe("/failure?existing=1&error=state_not_found#part");
    const ordinary = await invoke({ phase: "handler", errorURL: "/failure" });
    expect(ordinary.output.status).toBe(500); expect(ordinary.output.location).toBeNull();
    const invalid = await invoke({ oauth: true, errorURL: "relative/path", callback: "observe" });
    expect(invalid.output.status).toBe(500); expect(invalid.output.location).toBeNull(); expect(invalid.events).toEqual(["callback"]);
    return { oauth, ordinary, invalid };
  });
  for (const phase of ["before", "handler", "after"]) register(`${phase} keeps HTTP policy separate from API responses and native errors`, async invoke => {
    const rows = [];
    for (const transport of ["http", "native"]) for (const kind of ["plain", "api"]) for (const throwing of [false, true]) {
      const row = await invoke({ phase, transport, kind, throw: throwing, callback: "observe" });
      const calls = row.events.filter((event: string) => event === "callback").length;
      expect(calls).toBe(transport === "http" && !throwing && (kind === "plain" || phase === "before") ? 1 : 0);
      expect(row.output.thrown).toBe(transport === "native" || (kind === "plain" && throwing));
      if (kind === "api") expect(row.output.status).toBe(400);
      else if (row.output.thrown) expect(row.output.message).toBe("original failure");
      else { expect(row.output.status).toBe(500); expect(row.output.body).toBe(""); }
      rows.push({ transport, kind, throwing, ...row });
    }
    return rows;
  });

  register("transport hooks remain outside policy and are absent from native calls", async invoke => {
    const rows = [];
    for (const phase of ["onRequest", "onResponse"]) for (const transport of ["http", "native"]) {
      const row = await invoke({ phase, transport, callback: "observe" });
      expect(row.events).not.toContain("callback");
      expect(row.output.thrown).toBe(transport === "http");
      if (transport === "native") expect(row.output.value).toEqual({ ok: true });
      rows.push({ phase, transport, ...row });
    }
    return rows;
  });

  register("FOUND differs from numeric 302 and other redirect errors", async invoke => {
    const rows = [];
    for (const kind of ["found", "numeric302", "redirect307"]) for (const throwing of [false, true]) {
      const row = await invoke({ phase: "before", kind, throw: throwing, callback: "observe" });
      expect(row.output.thrown).toBe(false);
      expect(row.output.status).toBe(kind === "redirect307" ? 307 : 302);
      expect(row.output.location).toBe("/target");
      expect(row.events.includes("callback")).toBe(kind !== "found" && !throwing);
      rows.push({ kind, throwing, ...row });
    }
    return rows;
  });

  register("synchronous callback errors replace failures but async callbacks cannot delay responses", async invoke => {
    const ordinary = await invoke({ phase: "handler", callback: "throw" });
    expect(ordinary.output).toEqual({ thrown: true, message: "callback failure" });
    const api = await invoke({ phase: "handler", callback: "throw-api" });
    expect(api.output.status).toBe(502); expect(api.output.body).toEqual({ message: "callback failure" });
    const detached = await invoke({ phase: "handler", callback: "async" });
    expect(detached.output.status).toBe(500);
    expect(detached.events).toContain("callback-start"); expect(detached.events).not.toContain("callback-finish");
    expect(detached.completed).toEqual([...detached.events, "callback-finish"]);
    return { ordinary, api, detached };
  });

  register("decoding errors enter policy while endpoint validation returns an API response", async invoke => {
    const rows = [];
    for (const bodyCase of ["malformed", "media", "schema"]) {
      const row = await invoke({ bodyCase, callback: "observe" });
      expect(row.output.status).toBe(bodyCase === "media" ? 415 : 400);
      expect(row.events.includes("callback")).toBe(bodyCase !== "schema");
      rows.push({ bodyCase, ...row });
    }
    return rows;
  });

  register("error destinations append URL parameters and invalid destinations fail at invocation", async invoke => {
    const rows = [];
    for (const errorURL of ["/failure?existing=1#part", "https://example.com/failure?existing=1&#part"]) {
      const row = await invoke({ page: true, errorURL, query: "?error=CODE&error_description=%3Cscript%3E", customize: {} });
      expect(row.output.status).toBe(302);
      expect(row.output.location).toBe(errorURL.replace(/&?#part$/, "&error=CODE&error_description=%3Cscript%3E#part"));
      rows.push({ errorURL, ...row });
    }
    for (const errorURL of ["relative/path", "//example.com/error", "/\\example.com/error"]) {
      const row = await invoke({ page: true, errorURL, callback: "observe" });
      expect(row.output.status).toBe(500); expect(row.output.body).toBe(""); expect(row.events).toEqual(["callback"]);
      rows.push({ errorURL, ...row });
    }
    return rows;
  });

  register("native error pages require the original Request and ignore native query overrides", async invoke => {
    const missing = await invoke({ page: true, transport: "native", customize: {}, nativeQuery: { error: "IGNORED" }, callback: "observe" });
    expect(missing.output).toEqual({ thrown: true, message: "runtime error" }); expect(missing.events).toEqual([]);
    const present = await invoke({ page: true, transport: "native", nativeRequest: true, query: "?error=FROM_REQUEST", nativeQuery: { error: "IGNORED" }, customize: {}, needles: ["FROM_REQUEST", "IGNORED"] });
    expect(present.output.status).toBe(200); expect(present.output.matches).toEqual([true, false]);
    return { missing, present };
  });

  register("error-page escaping, first query value, and explicit customization remain observable", async invoke => {
    const rows = [];
    for (const [query, expected] of [["?error=FIRST&error=SECOND", "FIRST"], ["?error=&error=SECOND", "UNKNOWN"], ["?error=hello%20world", "UNKNOWN"], ["?error=it%27s", "it&#39;s"]]) {
      const row = await invoke({ page: true, query, customize: {}, needles: [`\n                ${expected}\n`] });
      expect(row.output.matches).toEqual([true]); rows.push(row);
    }
    const raw = `<img src=x onerror='x'> "quoted" &amp; &#39; &#x3c; &#60; suffix &unknown;`;
    const escaped = await invoke({ page: true, query: `?${new URLSearchParams({ error: "CODE", error_description: raw })}`, customize: {}, needles: ["&lt;img src=x onerror=&#39;x&#39;&gt; &quot;quoted&quot; &amp; &#39; &#x3c; &#60; suffix &amp;unknown;", "<img src=x"] });
    expect(escaped.output.matches).toEqual([true, false]); rows.push(escaped);
    const empty = await invoke({ page: true, query: "?error=CODE&error_description=", customize: {}, needles: ["We encountered an unexpected error."] });
    expect(empty.output.matches).toEqual([true]); rows.push(empty);
    const appearance = await invoke({ page: true, customize: { colors: { background: "pink", titleColor: "navy", cardBackground: "ivory" }, font: { defaultFamily: "monospace" }, size: { text4xl: "9rem" }, disableBackgroundGrid: true, disableCornerDecorations: true, disableTitleBorder: true }, needles: ["font-family: monospace", "--text-4xl: 9rem", "background: ivory", "color: navy", "border: 2px solid transparent", "background-image: linear-gradient", "<!-- Corner decorations -->"] });
    expect(appearance.output.matches).toEqual([true, true, true, true, true, false, false]); rows.push(appearance);
    return rows;
  });
}
