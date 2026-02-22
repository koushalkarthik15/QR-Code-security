import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "QRShield++ Web",
  description: "Web interface for QRShield++ threat detection."
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
