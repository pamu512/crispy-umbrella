Bundled placeholder so the Tauri host finds Compromised_user_Mac/ under Resource/scripts.

The included main.py is a no-op that reads RUMARK_DOMAINS / RUMARK_COOKIE and exits 0 so the
Data Lab / Armory "Run" path works in dev without your full Rumark + Tor stack.

For real Mac compromise crawls, replace this entire folder with the All_Scripts Compromised_user_Mac
project (RequestsTor, etc.) and re-run "Init" in the toolbox if you use a venv.
