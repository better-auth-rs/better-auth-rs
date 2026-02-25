"use client";

import { useSession, authClient } from "@/lib/auth-client";
import { useRouter } from "next/navigation";
import { useEffect, useState, useCallback } from "react";
import Link from "next/link";

interface SessionItem {
  id: string;
  token: string;
  userId: string;
  expiresAt: string;
  ipAddress?: string;
  userAgent?: string;
}

export default function SessionsPage() {
  const router = useRouter();
  const { data: session, isPending } = useSession();
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [loadingSessions, setLoadingSessions] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [revokingAll, setRevokingAll] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!isPending && !session) {
      router.push("/sign-in");
    }
  }, [isPending, session, router]);

  const fetchSessions = useCallback(async () => {
    setLoadingSessions(true);
    setError("");
    const { data, error: fetchError } = await authClient.listSessions();
    if (fetchError) {
      setError(fetchError.message || "Failed to load sessions");
    } else if (data) {
      setSessions(data as unknown as SessionItem[]);
    }
    setLoadingSessions(false);
  }, []);

  useEffect(() => {
    if (session) {
      fetchSessions();
    }
  }, [session, fetchSessions]);

  async function handleRevokeSession(token: string) {
    setRevoking(token);
    setError("");
    setMessage("");

    const { error: revokeError } = await authClient.revokeSession({
      token,
    });

    if (revokeError) {
      setError(revokeError.message || "Failed to revoke session");
    } else {
      setMessage("Session revoked");
      await fetchSessions();
    }

    setRevoking(null);
  }

  async function handleRevokeOtherSessions() {
    setRevokingAll(true);
    setError("");
    setMessage("");

    const { error: revokeError } = await authClient.revokeOtherSessions();

    if (revokeError) {
      setError(revokeError.message || "Failed to revoke sessions");
    } else {
      setMessage("All other sessions revoked");
      await fetchSessions();
    }

    setRevokingAll(false);
  }

  function isCurrentSession(s: SessionItem) {
    return session?.session?.token === s.token;
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
    <div className="container" style={{ marginTop: "2rem" }}>
      <div style={{ marginBottom: "1.5rem" }}>
        <Link href="/dashboard" style={{ fontSize: "0.875rem" }}>
          ← Back to Dashboard
        </Link>
      </div>

      <h1>Active Sessions</h1>
      <p className="muted">
        Manage your active sessions across devices
      </p>

      {error && <div className="error">{error}</div>}
      {message && <div className="success">{message}</div>}

      {loadingSessions ? (
        <p style={{ color: "var(--muted)", textAlign: "center" }}>
          Loading sessions...
        </p>
      ) : (
        <>
          <div className="stack">
            {sessions.map((s) => (
              <div key={s.id} className="card">
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                  }}
                >
                  <div>
                    {isCurrentSession(s) && (
                      <span className="badge" style={{ marginBottom: "0.5rem", display: "inline-block" }}>
                        Current session
                      </span>
                    )}
                    <div className="info-row" style={{ borderBottom: "none", padding: "0.25rem 0" }}>
                      <span className="info-label" style={{ marginRight: "1rem" }}>
                        IP
                      </span>
                      <span>{s.ipAddress || "Unknown"}</span>
                    </div>
                    <div className="info-row" style={{ borderBottom: "none", padding: "0.25rem 0" }}>
                      <span className="info-label" style={{ marginRight: "1rem" }}>
                        Expires
                      </span>
                      <span style={{ fontSize: "0.75rem" }}>
                        {new Date(s.expiresAt).toLocaleString()}
                      </span>
                    </div>
                    {s.userAgent && (
                      <div
                        style={{
                          fontSize: "0.7rem",
                          color: "var(--muted)",
                          marginTop: "0.25rem",
                          wordBreak: "break-all",
                          maxWidth: "280px",
                        }}
                      >
                        {s.userAgent.length > 80
                          ? s.userAgent.slice(0, 80) + "..."
                          : s.userAgent}
                      </div>
                    )}
                  </div>
                  {!isCurrentSession(s) && (
                    <button
                      className="danger"
                      style={{ width: "auto", fontSize: "0.75rem", padding: "0.375rem 0.75rem" }}
                      onClick={() => handleRevokeSession(s.token)}
                      disabled={revoking === s.token}
                    >
                      {revoking === s.token ? "..." : "Revoke"}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>

          {sessions.length > 1 && (
            <button
              className="danger"
              style={{ marginTop: "1rem" }}
              onClick={handleRevokeOtherSessions}
              disabled={revokingAll}
            >
              {revokingAll
                ? "Revoking..."
                : "Revoke All Other Sessions"}
            </button>
          )}
        </>
      )}
    </div>
  );
}
