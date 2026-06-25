"""
Screenshot Similarity Analysis Module
=======================================
Compares website screenshots to detect visual phishing clones.

Uses pixel-based and structural similarity metrics when possible,
with graceful degradation when image libraries are not available.
"""

from __future__ import annotations

import io
import os
import tempfile
from typing import Any
from urllib import request as url_request

# Optional image libraries
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


def compare_screenshots(
    suspect_screenshot_path: str,
    reference_screenshot_path: str,
) -> dict[str, Any]:
    """
    Compare two screenshot images for visual similarity.

    Args:
        suspect_screenshot_path: Path to the suspect domain screenshot.
        reference_screenshot_path: Path to the reference (legitimate) screenshot.

    Returns:
        Dict with similarity score and analysis.
    """
    if not HAS_PIL or not HAS_NUMPY:
        return {
            "available": False,
            "reason": "PIL/Pillow or numpy not installed",
        }

    try:
        suspect = Image.open(suspect_screenshot_path).convert("RGB")
        reference = Image.open(reference_screenshot_path).convert("RGB")

        # Resize to same dimensions for comparison
        target_size = (256, 256)
        suspect_resized = suspect.resize(target_size)
        reference_resized = reference.resize(target_size)

        # Convert to numpy arrays
        suspect_arr = np.array(suspect_resized, dtype=np.float32)
        reference_arr = np.array(reference_resized, dtype=np.float32)

        # Compute Mean Squared Error (MSE)
        mse = np.mean((suspect_arr - reference_arr) ** 2)

        # Convert MSE to similarity score (0-1)
        # MSE of 0 = identical, MSE of 65025 = completely different
        max_mse = 255.0 ** 2
        similarity = max(0.0, 1.0 - (mse / max_mse))

        # Compute Structural Similarity Index (simplified)
        suspect_gray = np.mean(suspect_arr, axis=2)
        reference_gray = np.mean(reference_arr, axis=2)

        # SSIM approximation using correlation
        s_mean = np.mean(suspect_gray)
        r_mean = np.mean(reference_gray)
        s_std = np.std(suspect_gray)
        r_std = np.std(reference_gray)

        if s_std > 0 and r_std > 0:
            covariance = np.mean((suspect_gray - s_mean) * (reference_gray - r_mean))
            correlation = covariance / (s_std * r_std)
            ssim = (2 * s_mean * r_mean + 0.01) * (2 * covariance + 0.03) / \
                   ((s_mean ** 2 + r_mean ** 2 + 0.01) * (s_std ** 2 + r_std ** 2 + 0.03))
        else:
            ssim = 0.0

        combined_similarity = 0.6 * similarity + 0.4 * max(0, min(1, ssim))

        return {
            "available": True,
            "similarity": round(float(combined_similarity), 4),
            "mse": round(float(mse), 2),
            "ssim": round(float(ssim), 4),
            "likely_clone": combined_similarity >= 0.75,
            "suspect_size": suspect.size,
            "reference_size": reference.size,
        }

    except Exception as exc:
        return {
            "available": False,
            "error": str(exc),
        }


def capture_screenshot(
    url: str,
    output_path: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """
    Capture a screenshot of a URL using Playwright.

    Requires Playwright to be installed.

    Args:
        url: The URL to capture.
        output_path: Path to save the screenshot. If None, uses temp file.
        timeout: Page load timeout.

    Returns:
        Dict with path to screenshot and status.
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return {"available": False, "reason": "Playwright not installed"}

    save_path = output_path or os.path.join(
        tempfile.gettempdir(),
        f"screenshot_{hash(url)}.png",
    )

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(
                viewport={"width": 1280, "height": 720},
                user_agent="TMGC-Screenshot/1.0",
            )
            page.goto(url, wait_until="networkidle", timeout=int(timeout * 1000))
            page.screenshot(path=save_path, full_page=True)
            browser.close()

        return {
            "available": True,
            "path": save_path,
            "url": url,
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}
