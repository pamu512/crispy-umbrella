"""
Social Media Screenshot Tool (library).

Public API:
- run_folder: process a folder of CSVs and write screenshots to an output folder.
- run_csv: process one CSV for a specific platform.
"""

from .runner import run_csv, run_folder

__all__ = ["run_csv", "run_folder"]

