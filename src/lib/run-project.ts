import { invoke } from "@tauri-apps/api/core"

/** IntelX Docker Compose stdin: query, start date, end date, search limit (bacongris workflow_runner). */
export type IntelxRunParams = {
  query: string
  startDate?: string
  endDate?: string
  searchLimit?: string
}

/** Social_MediaV2 main.py: -v1 target -v2 output -n num [--start-time][--end-time] (see README docker-run.sh). */
export type SocialMediaRunParams = {
  target: string
  startDate?: string
  endDate?: string
  numPerPlatform?: string
}

/** Brand Scout brand_scout.py: -ps / -sms / -all (README Phishing+ / Brand Scout). */
export type PhishingScanType = "PS" | "SMS" | "ALL"

export type PhishingRunParams = {
  scanType: PhishingScanType
  domains?: string
  keywords?: string
  startDate: string
  endDate: string
}

/** Compromised_user_Mac main.py: RUMARK_DOMAINS + optional RUMARK_COOKIE (non-interactive). */
export type CompromisedUserMacRunParams = {
  domains: string
  cookie?: string
}

/** When `scriptsRoot` is set, Rust resolves scripts from bundled `Resource/scripts` and uses AppData venv. */
export type InvokeRunProjectOpts = {
  scriptsRoot?: string | null
}

export async function invokeRunProject(
  workspacePath: string,
  projectName: string,
  scriptType: string,
  intelx: IntelxRunParams | null,
  social: SocialMediaRunParams | null = null,
  phishing: PhishingRunParams | null = null,
  compromisedMac: CompromisedUserMacRunParams | null = null,
  opts?: InvokeRunProjectOpts
): Promise<void> {
  if (projectName === "Intelx_Crawler") {
    const q = intelx?.query?.trim()
    if (!q) {
      throw new Error(
        "IntelX needs a target (email/domain/keyword) plus a time window. Use the IntelX run dialog."
      )
    }
  }
  if (projectName === "Social_MediaV2") {
    const t = social?.target?.trim()
    if (!t) {
      throw new Error(
        "Social Media V2 needs a target name and optional dates. Use the Social V2 run dialog."
      )
    }
  }
  if (projectName === "Phishing_and_Social_Media_All-in-one") {
    const p = phishing
    if (!p?.scanType || !p.startDate?.trim() || !p.endDate?.trim()) {
      throw new Error("Brand Scout needs scan type, start date, and end date. Use the Phishing+ run dialog.")
    }
    if ((p.scanType === "PS" || p.scanType === "ALL") && !(p.domains ?? "").trim()) {
      throw new Error("PS and ALL scans require domain(s).")
    }
    if ((p.scanType === "SMS" || p.scanType === "ALL") && !(p.keywords ?? "").trim()) {
      throw new Error("SMS and ALL scans require keyword(s).")
    }
  }
  await invoke("run_project_script", {
    workspacePath,
    projectName,
    scriptType,
    intelxQuery: projectName === "Intelx_Crawler" ? intelx?.query?.trim() ?? null : null,
    intelxStartDate: projectName === "Intelx_Crawler" ? intelx?.startDate?.trim() || null : null,
    intelxEndDate: projectName === "Intelx_Crawler" ? intelx?.endDate?.trim() || null : null,
    intelxSearchLimit: projectName === "Intelx_Crawler" ? intelx?.searchLimit?.trim() || null : null,
    socialMediaTarget: projectName === "Social_MediaV2" ? social?.target?.trim() ?? null : null,
    socialMediaStartDate: projectName === "Social_MediaV2" ? social?.startDate?.trim() || null : null,
    socialMediaEndDate: projectName === "Social_MediaV2" ? social?.endDate?.trim() || null : null,
    socialMediaNumPerPlatform:
      projectName === "Social_MediaV2" ? social?.numPerPlatform?.trim() || null : null,
    phishingScanType:
      projectName === "Phishing_and_Social_Media_All-in-one" ? phishing?.scanType ?? null : null,
    phishingDomains:
      projectName === "Phishing_and_Social_Media_All-in-one"
        ? phishing?.domains?.trim() || null
        : null,
    phishingKeywords:
      projectName === "Phishing_and_Social_Media_All-in-one"
        ? phishing?.keywords?.trim() || null
        : null,
    phishingStartDate:
      projectName === "Phishing_and_Social_Media_All-in-one"
        ? phishing?.startDate?.trim() || null
        : null,
    phishingEndDate:
      projectName === "Phishing_and_Social_Media_All-in-one"
        ? phishing?.endDate?.trim() || null
        : null,
    rumarkDomains:
      projectName === "Compromised_user_Mac" ? compromisedMac?.domains?.trim() ?? null : null,
    rumarkCookie:
      projectName === "Compromised_user_Mac"
        ? (compromisedMac?.cookie?.trim() || null)
        : null,
    scriptsRoot: opts?.scriptsRoot ?? null,
  })
}
