import type { Metadata } from "next"
import { Inter, JetBrains_Mono } from "next/font/google"

import { AppToastProvider } from "@/components/app-toast"
import { OllamaSettingsProvider } from "@/components/OllamaSettingsProvider"
import { PersistentAppLayout } from "@/components/persistent-app-layout"
import { AGENT_TAGLINE, SITE_TITLE } from "@/components/Sidebar"
import { ThemeProvider } from "@/components/theme-provider"
import { TooltipProvider } from "@/components/ui/tooltip"
import { WorkspaceProvider } from "@/components/WorkspaceProvider"

import "./globals.css"

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
})

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains",
  subsets: ["latin"],
})

export const metadata: Metadata = {
  title: SITE_TITLE,
  description: AGENT_TAGLINE,
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning className="dark">
      <body
        className={`${inter.variable} ${jetbrainsMono.variable} h-screen overflow-hidden bg-background font-sans antialiased`}
      >
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem={false}
          disableTransitionOnChange
        >
          <TooltipProvider>
            <OllamaSettingsProvider>
              <AppToastProvider>
                <WorkspaceProvider>
                  <PersistentAppLayout>{children}</PersistentAppLayout>
                </WorkspaceProvider>
              </AppToastProvider>
            </OllamaSettingsProvider>
          </TooltipProvider>
        </ThemeProvider>
      </body>
    </html>
  )
}
