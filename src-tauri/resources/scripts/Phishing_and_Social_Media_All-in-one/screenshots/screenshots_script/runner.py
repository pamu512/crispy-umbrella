import os
from typing import Callable, Dict, Optional

from .platforms import (
    screenshot_facebook,
    screenshot_generic,
    screenshot_instagram,
    screenshot_linkedin,
    screenshot_tiktok,
    screenshot_twitter,
)
from .utils import (
    csv_stem,
    default_output_root,
    detect_platform_from_csv_content,
    detect_platform_from_filename,
    ensure_dir,
    list_csv_files,
)


PlatformRunner = Callable[[str, str], None]


_PLATFORM_RUNNERS: Dict[str, Callable[..., None]] = {
    "facebook": screenshot_facebook,
    "generic": screenshot_generic,
    "instagram": screenshot_instagram,
    "linkedin": screenshot_linkedin,
    "tiktok": screenshot_tiktok,
    "twitter": screenshot_twitter,
}


def run_csv(platform: str, csv_file: str, output_folder: str, *, headless: bool = True) -> None:
    """
    Run screenshot for one CSV file of a specific platform.
    """
    platform = platform.lower().strip()
    if platform not in _PLATFORM_RUNNERS:
        raise ValueError(f"Unsupported platform: {platform}")

    ensure_dir(output_folder)
    _PLATFORM_RUNNERS[platform](csv_file, output_folder, headless=headless)


def run_folder(
    input_folder: str,
    *,
    output_root: Optional[str] = None,
    headless: bool = True,
    platform: Optional[str] = None,
) -> str:
    """
    Process all CSV files in a folder.

    By default platform is detected from the CSV filename:
    - facebook, instagram, linkedin (or linkin), tiktok, twitter (or x.com)
    If your CSV filenames do not contain platform names, pass platform=... (or use CLI --platform).

    Returns output_root path.
    """
    if not os.path.isdir(input_folder):
        raise ValueError(f"input_folder does not exist or is not a directory: {input_folder}")

    out_root = output_root or default_output_root(input_folder)
    ensure_dir(out_root)

    forced_platform: Optional[str] = None
    if platform is not None:
        forced_platform = platform.lower().strip()
        if forced_platform not in _PLATFORM_RUNNERS:
            raise ValueError(f"Unsupported platform: {forced_platform}")

    for csv_file in list_csv_files(input_folder):
        p = forced_platform or detect_platform_from_filename(csv_file) or detect_platform_from_csv_content(csv_file) or "generic"

        # Output layout: <output_root>/<csv_name>/...
        # (CSV name directly under <input>_output, as requested)
        csv_out = os.path.join(out_root, csv_stem(csv_file))
        run_csv(p, csv_file, csv_out, headless=headless)

    return out_root

