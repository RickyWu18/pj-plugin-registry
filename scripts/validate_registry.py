#!/usr/bin/env python3
"""Validate registry.json structure, URLs, and checksums.

Usage:
    python3 scripts/validate_registry.py                                        # Structure + URL checks
    python3 scripts/validate_registry.py --download-extensions-and-verify-checksums  # Download all ZIPs and verify SHA256
    python3 scripts/validate_registry.py --download-extensions-and-verify-folder-structure  # Download all ZIPs and check <plugin-id>/ top folder
"""

import argparse
import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

REQUIRED_TOP_LEVEL = ["registry_version", "extensions"]
REQUIRED_EXTENSION = ["id", "name", "version", "description", "author", "publisher", "license", "category", "platforms"]
VALID_PLATFORMS = ["linux-x86_64", "linux-arm64", "macos-x86_64", "macos-arm64", "windows-x86_64", "windows-arm64"]
VALID_CATEGORIES = ["data_loader", "data_stream", "message_parser", "parser", "toolbox", "widget"]


def validate_structure(registry: dict) -> list[str]:
    """Validate JSON structure. Returns list of errors."""
    errors = []

    # Check top-level fields
    for field in REQUIRED_TOP_LEVEL:
        if field not in registry:
            errors.append(f"Missing top-level field: {field}")

    if "extensions" not in registry:
        return errors

    if not isinstance(registry["extensions"], list):
        errors.append("'extensions' must be an array")
        return errors

    # Check each extension
    seen_ids = set()
    for i, ext in enumerate(registry["extensions"]):
        ext_id = ext.get("id", f"[index {i}]")

        # Check required fields
        for field in REQUIRED_EXTENSION:
            if field not in ext:
                errors.append(f"{ext_id}: missing required field '{field}'")

        # Check for duplicate IDs
        if ext.get("id"):
            if ext["id"] in seen_ids:
                errors.append(f"{ext_id}: duplicate extension id")
            seen_ids.add(ext["id"])

        # Check category
        if ext.get("category") and ext["category"] not in VALID_CATEGORIES:
            errors.append(f"{ext_id}: invalid category '{ext['category']}' (valid: {VALID_CATEGORIES})")

        # Check platforms structure
        platforms = ext.get("platforms", {})
        if not isinstance(platforms, dict):
            errors.append(f"{ext_id}: 'platforms' must be an object")
            continue

        for platform, data in platforms.items():
            if platform not in VALID_PLATFORMS:
                errors.append(f"{ext_id}: invalid platform '{platform}' (valid: {VALID_PLATFORMS})")

            if not isinstance(data, dict):
                errors.append(f"{ext_id}/{platform}: platform data must be an object")
                continue

            if "url" not in data:
                errors.append(f"{ext_id}/{platform}: missing 'url'")
            if "checksum" not in data:
                errors.append(f"{ext_id}/{platform}: missing 'checksum'")
            elif not data["checksum"].startswith("sha256:"):
                errors.append(f"{ext_id}/{platform}: checksum must start with 'sha256:'")

    # Check alphabetical order
    ids = [ext.get("id", "") for ext in registry["extensions"]]
    sorted_ids = sorted(ids)
    if ids != sorted_ids:
        errors.append("Extensions must be sorted alphabetically by id")
        # Find first out-of-order entry
        for i, (actual, expected) in enumerate(zip(ids, sorted_ids)):
            if actual != expected:
                errors.append(f"  First violation: '{actual}' at index {i}, expected '{expected}'")
                break

    return errors


def check_url_exists(url: str, timeout: int = 10) -> tuple[bool, str]:
    """Check if URL is accessible via HEAD request. Returns (success, error_message)."""
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "pj-plugin-registry-validator/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return True, ""
            return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, str(e.reason)
    except Exception as e:
        return False, str(e)


def verify_checksum(url: str, expected_checksum: str, timeout: int = 60) -> tuple[bool, str]:
    """Download file and verify SHA256 checksum. Returns (success, error_message)."""
    if not expected_checksum.startswith("sha256:"):
        return False, "Invalid checksum format"

    expected_hash = expected_checksum[7:]  # Remove "sha256:" prefix

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "pj-plugin-registry-validator/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            sha256 = hashlib.sha256()
            while chunk := resp.read(8192):
                sha256.update(chunk)
            actual_hash = sha256.hexdigest()

            if actual_hash == expected_hash:
                return True, ""
            return False, f"expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
    except Exception as e:
        return False, str(e)


def verify_folder_structure(url: str, ext_id: str, timeout: int = 60) -> tuple[bool, str]:
    """Download ZIP and verify every entry lives under a single '<ext_id>/' top folder.
    Returns (success, error_message)."""
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "pj-plugin-registry-validator/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = io.BytesIO(resp.read())

        with zipfile.ZipFile(data) as zf:
            names = zf.namelist()
            if not names:
                return False, "zip is empty"

            top_levels = {name.split("/", 1)[0] for name in names}
            if top_levels == {ext_id}:
                return True, ""
            return False, f"top-level entries {sorted(top_levels)}, expected only '{ext_id}/'"
    except zipfile.BadZipFile:
        return False, "not a valid zip file"
    except Exception as e:
        return False, str(e)


def validate_urls(registry: dict) -> list[str]:
    """Check all URLs are accessible. Returns list of errors."""
    errors = []
    for ext in registry.get("extensions", []):
        ext_id = ext.get("id", "unknown")
        for platform, data in ext.get("platforms", {}).items():
            url = data.get("url", "")
            if not url:
                continue

            success, msg = check_url_exists(url)
            if success:
                print(f"  ✓ {ext_id}/{platform}")
            else:
                errors.append(f"{ext_id}/{platform}: URL not accessible - {msg}")
                print(f"  ✗ {ext_id}/{platform}: {msg}")
    return errors


def validate_checksums(registry: dict) -> list[str]:
    """Verify all checksums. Returns list of errors."""
    errors = []
    for ext in registry.get("extensions", []):
        ext_id = ext.get("id", "unknown")
        for platform, data in ext.get("platforms", {}).items():
            url = data.get("url", "")
            checksum = data.get("checksum", "")

            if not url or not checksum:
                continue

            success, msg = verify_checksum(url, checksum)
            if success:
                print(f"  ✓ {ext_id}/{platform}")
            else:
                errors.append(f"{ext_id}/{platform}: checksum mismatch - {msg}")
                print(f"  ✗ {ext_id}/{platform}: {msg}")
    return errors


def validate_folder_structures(registry: dict) -> list[str]:
    """Verify every ZIP has the plugin id as its top folder. Returns list of errors."""
    errors = []
    for ext in registry.get("extensions", []):
        ext_id = ext.get("id", "unknown")
        for platform, data in ext.get("platforms", {}).items():
            url = data.get("url", "")
            if not url:
                continue

            success, msg = verify_folder_structure(url, ext_id)
            if success:
                print(f"  ✓ {ext_id}/{platform}")
            else:
                errors.append(f"{ext_id}/{platform}: bad folder structure - {msg}")
                print(f"  ✗ {ext_id}/{platform}: {msg}")
    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate registry.json")
    parser.add_argument("--download-extensions-and-verify-checksums", action="store_true",
                        help="Download all extension ZIPs and verify SHA256 checksums (slow)")
    parser.add_argument("--download-extensions-and-verify-folder-structure", action="store_true",
                        help="Download all extension ZIPs and verify the top folder is the plugin id (slow)")
    parser.add_argument("--skip-urls", action="store_true", help="Skip URL accessibility checks")
    parser.add_argument("registry_file", nargs="?", default="registry.json", help="Path to registry.json")
    args = parser.parse_args()

    registry_path = Path(args.registry_file)
    if not registry_path.exists():
        print(f"Error: {registry_path} not found")
        sys.exit(1)

    # Load and parse JSON
    print(f"Loading {registry_path}...")
    try:
        with open(registry_path) as f:
            registry = json.load(f)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        sys.exit(1)
    print("✓ Valid JSON")

    all_errors = []

    # Validate structure
    print("\nValidating structure...")
    structure_errors = validate_structure(registry)
    if structure_errors:
        for err in structure_errors:
            print(f"  ✗ {err}")
        all_errors.extend(structure_errors)
    else:
        ext_count = len(registry.get("extensions", []))
        print(f"  ✓ Structure valid ({ext_count} extensions)")

    # Validate URLs
    if not args.skip_urls:
        print("\nChecking URLs...")
        url_errors = validate_urls(registry)
        all_errors.extend(url_errors)

    # Verify checksums
    if args.download_extensions_and_verify_checksums:
        print("\nDownloading extensions and verifying checksums (this may take a while)...")
        checksum_errors = validate_checksums(registry)
        all_errors.extend(checksum_errors)

    # Verify folder structure
    if args.download_extensions_and_verify_folder_structure:
        print("\nDownloading extensions and verifying folder structure (this may take a while)...")
        all_errors.extend(validate_folder_structures(registry))

    # Summary
    print()
    if all_errors:
        print(f"✗ Validation failed with {len(all_errors)} error(s)")
        sys.exit(1)
    else:
        print("✓ All validations passed")
        sys.exit(0)


if __name__ == "__main__":
    main()
