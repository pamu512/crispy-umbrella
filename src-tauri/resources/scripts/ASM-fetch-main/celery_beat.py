"""
Celery beat scheduler entrypoint for ASM system.
"""
import subprocess

if __name__ == "__main__":
    subprocess.run(["celery", "-A", "src.tasks.scan_tasks", "beat", "--loglevel=info"])
