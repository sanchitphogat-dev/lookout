import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Lookout — Cybersecurity Threat Detection',
  description: 'Unified Cybersecurity Threat Detection Dashboard',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#0B0C0E] text-[#8A8F98] antialiased">
        {children}
      </body>
    </html>
  );
}
