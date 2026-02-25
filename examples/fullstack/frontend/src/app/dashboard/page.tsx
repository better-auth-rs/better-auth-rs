"use client";

import { useSession, signOut } from "@/lib/auth-client";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function DashboardPage() {
  const router = useRouter();
  const { data: session, isPending } = useSession();

  useEffect(() => {
    if (!isPending && !session) {
      router.push("/sign-in");
    }
  }, [isPending, session, router]);

  async function handleSignOut() {
    await signOut({
      fetchOptions: {
        onSuccess: () => {
          router.push("/");
        },
      },
    });
  }

  if (isPending) {
    return (
      <div className="container" style={{ marginTop: "4rem" }}>
        <p style={{ textAlign: "center", color: "var(--muted)" }}>
          Loading...
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
