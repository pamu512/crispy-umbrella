"""
Celery worker entrypoint for ASM system.
"""
import subprocess

if __name__ == "__main__":
    subprocess.run(["celery", "-A", "src.tasks.scan_tasks", "worker", "--loglevel=info"])
