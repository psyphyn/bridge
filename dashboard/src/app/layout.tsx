import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Bridge Admin",
  description: "Bridge zero-trust VPN administration dashboard",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-gray-950 text-gray-100 antialiased">
        <div className="flex min-h-screen">
          <Sidebar />
          <main className="flex-1 p-8">{children}</main>
        </div>
      </body>
    </html>
  );
}

function Sidebar() {
  return (
    <nav className="w-64 border-r border-gray-800 bg-gray-900 p-6">
      <div className="mb-8">
        <h1 className="text-xl font-bold tracking-tight">Bridge</h1>
        <p className="text-xs text-gray-500">Admin Dashboard</p>
      </div>
      <ul className="space-y-1">
        <NavItem href="/" label="Overview" />
        <NavItem href="/devices" label="Devices" />
        <NavItem href="/policies" label="Policies" />
      </ul>
    </nav>
  );
}

function NavItem({ href, label }: { href: string; label: string }) {
  return (
    <li>
      <a
        href={href}
        className="block rounded-lg px-3 py-2 text-sm text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
      >
        {label}
      </a>
    </li>
  );
}
