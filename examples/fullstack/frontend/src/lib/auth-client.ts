import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({
  baseURL: process.env.NEXT_PUBLIC_AUTH_URL || "http://localhost:3001",
  basePath: "/api/auth",
});

export const { useSession, signIn, signUp, signOut } = authClient;
