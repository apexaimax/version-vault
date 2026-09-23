# VersionVault

**Current release: 1.2 ZIP64 hardening build**

Compare two project ZIPs before you share, publish, or archive them—without uploading your source code.

VersionVault is a private, browser-only release review tool. It identifies file-level changes between an older and newer ZIP, verifies supported entries, and highlights common packaging risks directly in your browser tab.

## Why use it?

A release ZIP can look normal while still containing an unexpected file, duplicate path, changed configuration, credential-like string, or browser-extension permission. VersionVault provides a quick, readable verification pass before the archive leaves your hands.

Useful for:

- Comparing exported project builds
- Reviewing a ZIP before sending it to a tester, client, or collaborator
- Checking browser-extension packages and `manifest.json` permissions
- Producing a plain-text release verification report
- Keeping source review private instead of uploading archives to a third-party service

## What VersionVault checks

- Added, removed, changed, and unchanged files
- SHA-256 fingerprints for changed files
- CRC-32 integrity checks for supported ZIP entries
- Duplicate filenames and unsupported compression methods
- Common credential-like strings and sensitive-looking filenames
- Executable or binary filenames for review
- Chrome extension permissions in `manifest.json`
- Basic `package.json` metadata
- Downloadable plain-text release verification reports

## Privacy

VersionVault has no server endpoint and no analytics code. ZIP contents are processed in the current browser tab and are not uploaded by the application.

## ZIP64 support, with safety limits

Traditional ZIP metadata uses 32-bit size and offset fields. ZIP64 extends that format for modern archives with large files, central directories, or entry counts.

VersionVault supports the ZIP64 structures needed for safe bounded inspection:

- ZIP64 end-of-central-directory record and locator
- ZIP64 extended fields for entry sizes and local-header offsets
- Stored and deflated ZIP entries
- CRC-32 integrity validation after extraction

It intentionally rejects multi-disk ZIPs and archives or entries beyond its browser safety limits. This is bounded ZIP64 support: compatibility for modern ZIP metadata without pretending to be a universal archive engine.

## Verification

The repository includes a dedicated ZIP64 regression fixture. The smoke test verifies that VersionVault:

- Parses the ZIP64 fixture and extracts its expected file
- Computes file hashes and CRC values for inspected entries
- Rejects a deliberately corrupted ZIP64 entry
- Rejects a multi-disk archive declaration

Run the test with:

```bash
node tests/smoke.mjs
```

## Run

Open `index.html` in a modern browser. No build step or package installation is required.

The app uses the browser's `DecompressionStream` API for deflated entries. Very old browsers and uncommon ZIP compression methods may not be supported.

## What VersionVault does not prove

VersionVault is a release-review aid, not a security certification, malware scanner, signing system, or provenance verifier.

A clean result means the browser successfully inspected the supported archive content and found no matching heuristic concerns. SHA-256 values describe the bytes observed during that scan; they do not establish authorship, authenticity, safety, or the absence of vulnerabilities.
