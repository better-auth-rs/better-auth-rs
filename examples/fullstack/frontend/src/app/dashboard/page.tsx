"use client";

import { useSession, signOut } from "@/lib/auth-client";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

export default function DashboardPage() {
  const router = useRouter();
  const { data: session, isPending } = useSession();
  const [signingOut, setSigningOut] = useState(false);

  useEffect(() => {
    // Only redirect to sign-in if we're NOT in the middle of signing out.
    // Without this guard the useEffect fires before the signOut callback,
    // causing a flicker through /sign-in before landing on /.
    if (!isPending && !session && !signingOut) {
      router.push("/sign-in");
    }
  }, [isPending, session, signingOut, router]);

  async function handleSignOut() {
    setSigningOut(true);
    await signOut({
      fetchOptions: {
        onSuccess: () => {
          router.push("/");
        },
      },
    });
  }

  if (isPending || signingOut) {
    return (
      <div className="container" style={{ marginTop: "4rem" }}>
        <p style={{ textAlign: "center", color: "var(--muted)" }}>
          {signingOut ? "Signing out..." : "Loading..."}
        </p>
      </div>
    );
  }

  if (!session) {
    return null;
  }

  return (
    <div>
      <nav className="nav">
        <span className="nav-brand">better-auth-rs example</span>
        <span className="badge">dashboard</span>
      </nav>
      <div className="container">
        <div className="card">
          <h2>Dashboard</h2>
          <p className="muted">
            You are authenticated. Session data from better-auth-rs:
          </p>

          <div style={{ marginBottom: "1.5rem" }}>
            <div className="info-row">
              <span className="info-label">Name</span>
              <span>{session.user.name}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Email</span>
              <span>{session.user.email}</span>
            </div>
            <div className="info-row">
              <span className="info-label">User ID</span>
              <span style={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                {session.user.id}
              </span>
            </div>
            <div className="info-row">
              <span className="info-label">Created</span>
              <span>
                {new Date(session.user.createdAt).toLocaleDateString()}
              </span>
            </div>
            {session.session?.expiresAt && (
              <div className="info-row">
                <span className="info-label">Session Expires</span>
                <span style={{ fontSize: "0.75rem" }}>
                  {new Date(session.session.expiresAt).toLocaleString()}
                </span>
              </div>
            )}
            {session.session?.token && (
              <div className="info-row">
                <span className="info-label">Session Token</span>
                <span
                  style={{
                    fontFamily: "monospace",
                    fontSize: "0.65rem",
                    wordBreak: "break-all",
                    maxWidth: "200px",
                    textAlign: "right",
                  }}
                >
                  {session.session.token.slice(0, 16)}…
                </span>
              </div>
            )}
          </div>

          <div className="stack">
            <button className="danger" onClick={handleSignOut}>
              Sign Out
            </button>
            <button className="secondary" onClick={() => router.push("/")}>
              Back to Home
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
