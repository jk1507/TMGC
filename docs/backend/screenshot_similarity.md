# backend/screenshot_similarity.py - Screenshot Similarity Analysis

Compares website screenshots to detect visual phishing clones.

## Features
- Pixel-based similarity metrics
- Structural similarity (SSIM approximation)
- Graceful degradation when image libraries unavailable

## Prerequisites
```bash
pip install Pillow numpy
```

## Functions

### `compare_screenshots(suspect_screenshot_path, reference_screenshot_path)`
Compare two screenshot images for visual similarity.

**Returns dict with:**
- `available`: bool
- `similarity`: 0.0-1.0 combined similarity
- `mse`: Mean Squared Error
- `ssim`: Structural Similarity Index
- `likely_clone`: True if similarity >= 0.75
- `suspect_size`: Image dimensions
- `reference_size`: Image dimensions

**Method:**
1. Resize both images to 256x256
2. Compute MSE (pixel difference)
3. Compute SSIM approximation (correlation)
4. Combine: 0.6 * MSE_similarity + 0.4 * SSIM

### `capture_screenshot(url, output_path=None, timeout=10.0)`
Capture a screenshot of a URL using Playwright.

**Args:**
- `url`: URL to capture
- `output_path`: Save path (default: temp file)
- `timeout`: Page load timeout

**Returns dict with:**
- `available`: bool
- `path`: Path to screenshot file
- `url`: Captured URL
