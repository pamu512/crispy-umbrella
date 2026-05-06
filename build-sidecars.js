#!/usr/bin/env node
/**
 * Freeze ingestion Python projects with PyInstaller and rename outputs for Tauri `bundle.externalBin`.
 *
 * Prerequisites (host machine):
 *   python3 -m venv .venv && .venv/bin/pip install pyinstaller
 *   Install each script’s deps: pip install -r src-tauri/resources/scripts/<Project>/requirements.txt
 *   Or set PYTHON=/path/to/python with PyInstaller + deps already installed (e.g. pipx).
 *
 * Output: src-tauri/binaries/<sidecar-base>-<rustc-target-triple>[.exe]
 * Tauri resolves `binaries/<sidecar-base>` at bundle time to that file (see tauri.conf.json → bundle.externalBin).
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname);
const BINARIES_DIR = path.join(ROOT, "src-tauri", "binaries");

/** @type {{ dir: string; entry: string; sidecarBase: string }[]} */
/** Lighter / fewer deps first so missing venv fails faster; IntelX (pandas) last. */
const SIDECARS = [
  {
    dir: "src-tauri/resources/scripts/Compromised_user_Mac",
    entry: "main.py",
    sidecarBase: "mac-stealer",
  },
  {
    dir: "src-tauri/resources/scripts/Ransomware_live_event_victim",
    entry: "main.py",
    sidecarBase: "ransomware-live",
  },
  {
    dir: "src-tauri/resources/scripts/CVE_Project_NVD",
    entry: "main.py",
    sidecarBase: "cve-nvd",
  },
  {
    dir: "src-tauri/resources/scripts/IOCs-crawler-main",
    entry: "run_news_crawler.py",
    sidecarBase: "ioc-news-crawler",
  },
  {
    dir: "src-tauri/resources/scripts/Intelx_Crawler",
    entry: "intelx_native_sync.py",
    sidecarBase: "intelx-scraper",
  },
];

function getRustTargetTriple() {
  const { platform, arch } = process;
  if (platform === "darwin") {
    if (arch === "arm64") return "aarch64-apple-darwin";
    if (arch === "x64") return "x86_64-apple-darwin";
    throw new Error(`Unsupported macOS arch: ${arch}`);
  }
  if (platform === "win32") {
    if (arch === "x64") return "x86_64-pc-windows-msvc";
    if (arch === "arm64") return "aarch64-pc-windows-msvc";
    if (arch === "ia32") return "i686-pc-windows-msvc";
    throw new Error(`Unsupported Windows arch: ${arch}`);
  }
  if (platform === "linux") {
    if (arch === "x64") return "x86_64-unknown-linux-gnu";
    if (arch === "arm64") return "aarch64-unknown-linux-gnu";
    throw new Error(`Unsupported Linux arch: ${arch}`);
  }
  throw new Error(`Unsupported platform: ${platform}`);
}

/**
 * Same triple Cargo uses for the default host target (matches `rustc --print host-tuple`).
 * Prefer over `process.arch` when Node is x64-under-Rosetta but Rust builds aarch64, etc.
 */
function getEffectiveRustTriple() {
  const fromEnv =
    process.env.TAURI_ENV_TARGET_TRIPLE?.trim() ||
    process.env.CARGO_BUILD_TARGET?.trim();
  if (fromEnv) return fromEnv;

  try {
    const tuple = execSync("rustc --print host-tuple", {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    })
      .trim()
      .split(/\r?\n/)[0]
      ?.trim();
    if (tuple) return tuple;
  } catch {
    /* fall through */
  }

  try {
    const out = execSync("rustc -vV", {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    const m = out.match(/host:\s*(\S+)/);
    if (m) return m[1].trim();
  } catch {
    /* fall through */
  }

  return getRustTargetTriple();
}

function windowsExeSuffix() {
  return process.platform === "win32" ? ".exe" : "";
}

function pyinstallerArtifactName(internalName) {
  return process.platform === "win32" ? `${internalName}.exe` : internalName;
}

function findProjectVenvPython() {
  if (process.platform === "win32") {
    const candidates = [
      path.join(ROOT, ".venv", "Scripts", "python.exe"),
      path.join(ROOT, "src-tauri", ".venv", "Scripts", "python.exe"),
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
  } else {
    const candidates = [
      path.join(ROOT, ".venv", "bin", "python3"),
      path.join(ROOT, ".venv", "bin", "python"),
      path.join(ROOT, "src-tauri", ".venv", "bin", "python3"),
      path.join(ROOT, "src-tauri", ".venv", "bin", "python"),
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
  }
  return null;
}

function getPythonExecutable() {
  if (process.env.PYTHON && String(process.env.PYTHON).trim()) {
    return String(process.env.PYTHON).trim();
  }
  const venvPy = findProjectVenvPython();
  if (venvPy) return venvPy;
  return process.platform === "win32" ? "python" : "python3";
}

function ensurePyInstaller(pythonCmd) {
  try {
    execSync(`${quoteShell(pythonCmd)} -m PyInstaller --version`, {
      stdio: "pipe",
      encoding: "utf8",
      shell: true,
    });
  } catch {
    console.error(
      `[build-sidecars] PyInstaller not found for ${pythonCmd}. Install: ${pythonCmd} -m pip install pyinstaller`,
    );
    process.exit(1);
  }
}

function rmrf(p) {
  fs.rmSync(p, { recursive: true, force: true });
}

function main() {
  const pythonCmd = getPythonExecutable();
  ensurePyInstaller(pythonCmd);

  const triple = getEffectiveRustTriple();
  const exeSuffix = windowsExeSuffix();
  fs.mkdirSync(BINARIES_DIR, { recursive: true });

  console.log(`[build-sidecars] Host Rust triple: ${triple}`);
  console.log(`[build-sidecars] Output directory: ${BINARIES_DIR}`);

  for (const sidecar of SIDECARS) {
    const scriptDir = path.join(ROOT, sidecar.dir);
    const entryPath = path.join(scriptDir, sidecar.entry);
    if (!fs.existsSync(entryPath)) {
      console.error(`[build-sidecars] Missing entry: ${entryPath}`);
      process.exit(1);
    }

    const internalName = `_pio_${sidecar.sidecarBase.replace(/[^a-z0-9_-]/gi, "_")}`;
    const workPath = path.join(BINARIES_DIR, `.work-${sidecar.sidecarBase}`);
    const distPath = path.join(BINARIES_DIR, `.dist-${sidecar.sidecarBase}`);
    const specPath = path.join(BINARIES_DIR, `.spec-${sidecar.sidecarBase}`);

    rmrf(workPath);
    rmrf(distPath);
    rmrf(specPath);
    fs.mkdirSync(workPath, { recursive: true });
    fs.mkdirSync(distPath, { recursive: true });
    fs.mkdirSync(specPath, { recursive: true });

    const pyArgs = [
      "-m",
      "PyInstaller",
      "--onefile",
      "--clean",
      "-y",
      "--name",
      internalName,
      "--distpath",
      distPath,
      "--workpath",
      workPath,
      "--specpath",
      specPath,
    ];
    if (sidecar.sidecarBase === "ioc-news-crawler") {
      pyArgs.push("--collect-submodules", "news");
      pyArgs.push("--collect-data", "stealth_requests");
      const sep = process.platform === "win32" ? ";" : ":";
      const newsCommon = path.join(scriptDir, "news", "common");
      pyArgs.push("--add-data", `${newsCommon}${sep}news/common`);
    }
    if (sidecar.sidecarBase === "intelx-scraper") {
      const sharedUtils = path.join(
        ROOT,
        "src-tauri/resources/scripts/shared_utils",
      );
      const sep = process.platform === "win32" ? ";" : ":";
      pyArgs.push("--add-data", `${sharedUtils}${sep}shared_utils`);
    }
    pyArgs.push(sidecar.entry);

    console.log(`\n[build-sidecars] Building ${sidecar.sidecarBase} (${scriptDir}) …`);
    const cmdline = [quoteShellArg(pythonCmd), ...pyArgs.map(quoteShellArg)].join(" ");
    execSync(cmdline, {
      cwd: scriptDir,
      stdio: "inherit",
      shell: true,
      env: process.env,
    });

    const builtName = pyinstallerArtifactName(internalName);
    const builtPath = path.join(distPath, builtName);
    if (!fs.existsSync(builtPath)) {
      console.error(`[build-sidecars] Expected artifact not found: ${builtPath}`);
      process.exit(1);
    }

    const finalName = `${sidecar.sidecarBase}-${triple}${exeSuffix}`;
    const finalPath = path.join(BINARIES_DIR, finalName);
    fs.renameSync(builtPath, finalPath);
    rmrf(workPath);
    rmrf(distPath);
    rmrf(specPath);

    console.log(`[build-sidecars] → ${finalPath}`);
  }

  console.log("\n[build-sidecars] Done.");
}

/** Minimal quoting for `ensurePyInstaller` shell invocation only. */
function quoteShell(cmd) {
  if (/[\s'"\\]/.test(cmd)) {
    return `"${String(cmd).replace(/"/g, '\\"')}"`;
  }
  return cmd;
}

/** Quote one argv segment for `execSync(..., { shell: true })` on Unix and Windows. */
function quoteShellArg(arg) {
  const s = String(arg);
  if (process.platform === "win32") {
    if (/[\s"]/.test(s)) return `"${s.replace(/"/g, '\\"')}"`;
    return s;
  }
  if (/\s|'/.test(s) || s === "") return `'${s.replace(/'/g, `'\\''`)}'`;
  return s;
}

main();
