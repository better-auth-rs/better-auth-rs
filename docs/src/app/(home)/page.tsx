import Link from 'next/link';

export default function HomePage() {
  return (
    <div className="flex flex-col justify-center text-center flex-1 px-4">
      <h1 className="text-4xl font-bold mb-4">Better Auth <span className="opacity-50">in Rust</span></h1>
      <p className="text-lg text-fd-muted-foreground mb-8 max-w-2xl mx-auto">
        A comprehensive, plugin-based authentication framework for Rust.
        Type-safe, async-first, and extensible.
      </p>
      <div className="flex gap-4 justify-center mb-12">
        <Link
          href="/docs"
          className="px-6 py-3 rounded-lg bg-fd-primary text-fd-primary-foreground font-medium hover:opacity-90 transition-opacity"
        >
          Get Started
        </Link>
        <Link
          href="/docs/reference/api-routes"
          className="px-6 py-3 rounded-lg border border-fd-border font-medium hover:bg-fd-accent transition-colors"
        >
          API Reference
        </Link>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto text-left">
        <div className="p-6 rounded-lg border border-fd-border">
          <h3 className="font-semibold mb-2">Plugin Architecture</h3>
          <p className="text-sm text-fd-muted-foreground">
            Add email/password, sessions, OAuth, and more through composable plugins.
          </p>
        </div>
        <div className="p-6 rounded-lg border border-fd-border">
          <h3 className="font-semibold mb-2">Database Flexibility</h3>
          <p className="text-sm text-fd-muted-foreground">
            In-memory adapter for development, PostgreSQL for production. Bring your own adapter.
          </p>
        </div>
        <div className="p-6 rounded-lg border border-fd-border">
          <h3 className="font-semibold mb-2">Framework Integration</h3>
          <p className="text-sm text-fd-muted-foreground">
            First-class Axum support with automatic route mounting. More frameworks coming soon.
          </p>
        </div>
      </div>
    </div>
  );
}
