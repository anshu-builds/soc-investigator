import type { Metadata } from 'next'
import './globals.css'
import { AppShell } from '@/components/layout/AppShell'
// DESIGN PREVIEW ONLY (remove before production): synthetic auth + /api fixtures
import { DesignPreviewBootstrap } from '@/preview/DesignPreviewBootstrap'

export const metadata: Metadata = {
  title: 'SOC Investigator | Enterprise SIEM & Incident Response',
  description: 'Evidence-grounded conversational Security Operations Center investigation platform',
  keywords: ['SOC', 'security', 'incident response', 'threat detection', 'MITRE ATT&CK', 'SIEM'],
  icons: {
    icon: '/icon.svg',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="antialiased bg-canvas text-ink-primary">
        {/* DESIGN PREVIEW ONLY (remove before production) */}
        <DesignPreviewBootstrap />
        <AppShell>{children}</AppShell>
      </body>
    </html>
  )
}
