"use client";

import { useSession } from "@/lib/auth-client";
import Link from "next/link";

export default function Home() {
  const { data: session, isPending } = useSession();

  return (
    <div>
      <nav className="nav">
        <span className="nav-brand">better-auth-rs example</span>
        <span className="badge">fullstack</span>
      </nav>
      <div className="container">
        <div className="card">
          <h1>better-auth + better-auth-rs</h1>
          <p className="muted">
            Integration example: better-auth frontend SDK talking to a
            better-auth-rs (Rust/Axum) backend.
          </p>

          {isPending ? (
            <p style={{ textAlign: "center", color: "var(--muted)" }}>
              Loading...
            </p>
          ) : session ? (
            <div className="stack">
              <p>
                Signed in as <strong>{session.user.email}</strong>
              </p>
              <Link href="/dashboard">
                <button>Go to Dashboard</button>
              </Link>
            </div>
          ) : (
            <div className="stack">
              <Link href="/sign-in">
                <button>Sign In</button>
              </Link>
              <Link href="/sign-up">
                <button className="secondary">Create Account</button>
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
