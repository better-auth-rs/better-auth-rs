"use client";

import { useSession, authClient } from "@/lib/auth-client";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import Link from "next/link";

type PasskeyRecord = {
  id: string;
  name?: string;
  createdAt: string;
  deviceType: string;
  backedUp: boolean;
};

export default function SettingsPage() {
  const router = useRouter();
  const { data: session, isPending } = useSession();

  // Profile form
  const [name, setName] = useState("");
  const [profileLoading, setProfileLoading] = useState(false);
  const [profileMessage, setProfileMessage] = useState("");
  const [profileError, setProfileError] = useState("");

  // Password form
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [passwordMessage, setPasswordMessage] = useState("");
  const [passwordError, setPasswordError] = useState("");

  // Passkey management
  const [passkeys, setPasskeys] = useState<PasskeyRecord[]>([]);
  const [passkeysLoading, setPasskeysLoading] = useState(false);
  const [passkeyName, setPasskeyName] = useState("");
  const [passkeyMessage, setPasskeyMessage] = useState("");
  const [passkeyError, setPasskeyError] = useState("");
  const [registeringPasskey, setRegisteringPasskey] = useState(false);
  const [deletingPasskeyId, setDeletingPasskeyId] = useState<string | null>(null);

  useEffect(() => {
    if (!isPending && !session) {
      router.push("/sign-in");
    }
  }, [isPending, session, router]);

  // Populate name field when session loads
  useEffect(() => {
    if (session?.user?.name) {
      setName(session.user.name);
    }
  }, [session]);

  useEffect(() => {
    if (!session) {
      return;
    }

    void loadPasskeys();
  }, [session]);

  async function handleUpdateProfile(e: React.FormEvent) {
    e.preventDefault();
    setProfileError("");
    setProfileMessage("");
    setProfileLoading(true);

    await authClient.updateUser(
      { name },
      {
        onSuccess: () => {
          setProfileMessage("Profile updated successfully");
        },
        onError: (ctx) => {
          setProfileError(ctx.error.message || "Failed to update profile");
        },
      },
    );

    setProfileLoading(false);
  }

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault();
    setPasswordError("");
    setPasswordMessage("");

    if (newPassword !== confirmPassword) {
      setPasswordError("Passwords do not match");
      return;
    }

    if (newPassword.length < 8) {
      setPasswordError("New password must be at least 8 characters");
      return;
    }

    setPasswordLoading(true);

    await authClient.changePassword(
      {
        currentPassword,
        newPassword,
        revokeOtherSessions: true,
      },
      {
        onSuccess: () => {
          setPasswordMessage("Password changed successfully");
          setCurrentPassword("");
          setNewPassword("");
          setConfirmPassword("");
        },
        onError: (ctx) => {
          setPasswordError(ctx.error.message || "Failed to change password");
        },
      },
    );

    setPasswordLoading(false);
  }

  async function loadPasskeys() {
    setPasskeysLoading(true);

    const result = await authClient.$fetch<PasskeyRecord[]>("/passkey/list-user-passkeys", {
      method: "GET",
      throw: false,
    });

    if (result.data) {
      setPasskeys(result.data);
      setPasskeyError("");
    } else if (result.error) {
      setPasskeyError(result.error.message || "Failed to load passkeys");
    }

    setPasskeysLoading(false);
  }

  async function handleRegisterPasskey() {
    setPasskeyError("");
    setPasskeyMessage("");
    setRegisteringPasskey(true);

    const name =
      passkeyName.trim() || session?.user.email || session?.user.name || "My Passkey";

    const result = await authClient.passkey.addPasskey({
      name,
      authenticatorAttachment: "cross-platform",
    });

    if (result.error) {
      setPasskeyError(result.error.message || "Failed to register passkey");
      setRegisteringPasskey(false);
      return;
    }

    setPasskeyName("");
    setPasskeyMessage("Passkey registered successfully");
    await loadPasskeys();
    setRegisteringPasskey(false);
  }

  async function handleDeletePasskey(id: string) {
    setPasskeyError("");
    setPasskeyMessage("");
    setDeletingPasskeyId(id);

    const result = await authClient.$fetch<{ status: boolean }>("/passkey/delete-passkey", {
      method: "POST",
      body: { id },
      throw: false,
    });

    if (result.error) {
      setPasskeyError(result.error.message || "Failed to delete passkey");
      setDeletingPasskeyId(null);
      return;
    }

    setPasskeyMessage("Passkey removed");
    await loadPasskeys();
    setDeletingPasskeyId(null);
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

      <h1>Settings</h1>
      <p className="muted">Manage your account settings</p>

      {/* Update Profile */}
      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <h2>Profile</h2>
        <form onSubmit={handleUpdateProfile}>
          {profileError && <div className="error">{profileError}</div>}
          {profileMessage && (
            <div className="success">{profileMessage}</div>
          )}

          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            value={session.user.email}
            disabled
            style={{ opacity: 0.5 }}
          />

          <label htmlFor="name">Name</label>
          <input
            id="name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />

          <button type="submit" disabled={profileLoading}>
            {profileLoading ? "Saving..." : "Update Profile"}
          </button>
        </form>
      </div>

      {/* Change Password */}
      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <h2>Change Password</h2>
        <form onSubmit={handleChangePassword}>
          {passwordError && <div className="error">{passwordError}</div>}
          {passwordMessage && (
            <div className="success">{passwordMessage}</div>
          )}

          <label htmlFor="currentPassword">Current Password</label>
          <input
            id="currentPassword"
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
            minLength={8}
          />

          <label htmlFor="newPassword">New Password</label>
          <input
            id="newPassword"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            minLength={8}
          />

          <label htmlFor="confirmPassword">Confirm New Password</label>
          <input
            id="confirmPassword"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            minLength={8}
          />

          <button type="submit" disabled={passwordLoading}>
            {passwordLoading ? "Changing..." : "Change Password"}
          </button>
        </form>
      </div>

      {/* Passkeys */}
      <div className="card">
        <h2>Passkeys</h2>
        <p className="muted">Register a passkey for passwordless sign-in.</p>

        {passkeyError && <div className="error">{passkeyError}</div>}
        {passkeyMessage && <div className="success">{passkeyMessage}</div>}

        <div style={{ marginBottom: "1rem" }}>
          <label htmlFor="passkeyName">Passkey Name</label>
          <input
            id="passkeyName"
            type="text"
            value={passkeyName}
            onChange={(e) => setPasskeyName(e.target.value)}
            placeholder="Laptop, Phone, Security Key"
          />

          <button type="button" onClick={handleRegisterPasskey} disabled={registeringPasskey}>
            {registeringPasskey ? "Waiting for passkey..." : "Register Passkey"}
          </button>
        </div>

        <div className="stack">
          {passkeysLoading ? (
            <p className="muted">Loading passkeys...</p>
          ) : passkeys.length === 0 ? (
            <p className="muted">No passkeys registered yet.</p>
          ) : (
            passkeys.map((passkey) => (
              <div key={passkey.id} className="passkey-row">
                <div>
                  <div className="passkey-name">{passkey.name || "Unnamed Passkey"}</div>
                  <div className="passkey-meta">
                    {passkey.deviceType}
                    {passkey.backedUp ? " • backed up" : ""}
                    {" • "}
                    {new Date(passkey.createdAt).toLocaleDateString()}
                  </div>
                </div>
                <button
                  type="button"
                  className="danger-inline"
                  onClick={() => handleDeletePasskey(passkey.id)}
                  disabled={deletingPasskeyId === passkey.id}
                >
                  {deletingPasskeyId === passkey.id ? "Removing..." : "Remove"}
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
