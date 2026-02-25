import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "better-auth-rs fullstack example",
  description:
    "Integration example using better-auth (frontend) with better-auth-rs (backend)",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
