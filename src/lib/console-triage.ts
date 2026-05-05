/**
 * Map host console log lines to operator-facing Barney briefing bodies (dedupe by key in UI).
 */
export function triageFromConsoleLine(message: string): { key: string; body: string } | null {
  const m = message
  const u = m.toUpperCase()

  if (u.includes("INTELX_API_KEY") || m.includes("INTELX_API_KEY is not set")) {
    return {
      key: "intelx-api-key",
      body:
        "## Hunter note — IntelX API key\n\nThe host console shows IntelX starting **without** `INTELX_API_KEY`. Export your Intelligence X API key in the **same environment** you use to launch CTI Command Center, then restart the app:\n\n```bash\nexport INTELX_API_KEY='your-key'\n```\n\nThe canonical SQLite vault path comes from **`CTI_DB_PATH`** / **`VAULT_PATH`** (default: OS app data, e.g. macOS `~/Library/Application Support/com.pamu512.crispyumbrella/cti-app/`). Armory tools resolve scripts via bundled `resources/scripts/`.\n\nRun **Initialize Hunter Sync** again after export.",
    }
  }

  if (m.includes("ModuleNotFoundError") && m.includes("requests")) {
    return {
      key: "requests-missing",
      body:
        "## Hunter note — Python `requests`\n\nConsole shows `ModuleNotFoundError: requests`. Current `intelx_native_sync.py` uses **stdlib `urllib` only** — if you still see this, rebuild/restart so the updated script is loaded. Otherwise install deps in a venv and point **`CTI_PYTHON`** at that interpreter.",
    }
  }

  if (
    m.includes("Docker Compose not found") ||
    (m.includes("docker") && m.includes("compose") && (m.includes("not found") || u.includes("NO SUCH FILE")))
  ) {
    return {
      key: "docker-compose",
      body:
        "## Hunter note — Docker\n\nConsole hints Docker Compose is missing or not on PATH. Install **Docker Desktop**, verify `docker compose version`, then retry Docker-based Armory tools.",
    }
  }

  if (m.includes("CTI_DB_PATH") && m.includes("not")) {
    return {
      key: "vault-path",
      body:
        "## Hunter note — Vault path\n\nConsole referenced vault path problems. Confirm **`CTI_DB_PATH`** points at a vault file that exists and is readable (permissions). On macOS the default folder is **`~/Library/Application Support/com.pamu512.crispyumbrella/cti-app/`** (`cti_vault.db` or legacy `vault.db`). Vitals should show IOC/CVE counts once linked.",
    }
  }

  return null
}
