"use client";

import { useState, useEffect } from "react";
import { signIn, useSession } from "@/lib/auth-client";
import { useRouter } from "next/navigation";
import Link from "next/link";

export default function SignInPage() {
  const router = useRouter();
  const { data: session, isPending } = useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // Redirect already-authenticated users to the dashboard.
  useEffect(() => {
    if (!isPending && session) {
      router.push("/dashboard");
    }
  }, [isPending, session, router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    const { error } = await signIn.email(
      { email, password },
      {
        onSuccess: () => {
          router.push("/dashboard");
        },
        onError: (ctx) => {
          setError(ctx.error.message || "Sign in failed");
        },
      },
    );

    if (error) {
      setError(error.message || "Invalid email or password");
    }

    setLoading(false);
  }

  return (
    <div className="container" style={{ marginTop: "4rem" }}>
      <div className="card">
        <h2>Sign In</h2>
        <p className="muted">Sign in to your account.</p>

        {error && <div className="error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            required
          />

          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Your password"
            required
          />

          <button type="submit" disabled={loading}>
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <div className="form-footer">
          Don&apos;t have an account? <Link href="/sign-up">Sign up</Link>
        </div>
      </div>
    </div>
  );
}
