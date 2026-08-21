import type { Metadata } from 'next'
import './globals.css'
import { Sidebar } from '@/components/layout/Sidebar'
import { GradientBackground } from '@/components/ui/jade-sky'

export const metadata: Metadata = {
  title: 'SOC Investigator | PS 114',
  description: 'Evidence-grounded conversational Security Operations Center investigation platform',
  keywords: ['SOC', 'security', 'incident response', 'threat detection', 'MITRE ATT&CK'],
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="antialiased">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  )
}

function AppShell({ children }: { children: React.ReactNode }) {
  // Pages that don't use the sidebar (login)
  return (
    <div className="relative min-h-screen overflow-hidden">
      <GradientBackground className="pointer-events-none absolute inset-0" />
      <Sidebar />
      <main className="relative z-10 min-h-screen ml-[280px] overflow-y-auto">
        {children}
      </main>
    </div>
  )
}
