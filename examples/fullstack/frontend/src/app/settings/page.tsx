"use client";

import { useSession, authClient } from "@/lib/auth-client";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import Link from "next/link";

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
      <div className="card">
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
    </div>
  );
}
