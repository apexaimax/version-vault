# VersionVault

VersionVault is a browser-only MVP for investigating changes between two project ZIP packages.

## What it does

- Reads ZIPs locally in the browser.
- Compares file names and SHA-256 file fingerprints.
- Reports added, removed, changed, and unchanged files.
- Checks common source/config files for credential-like patterns.
- Flags sensitive-looking filenames and executable binaries.
- Inspects Chrome extension `manifest.json` permissions.
- Inspects `package.json` name/version/dependency counts.
- Exports a plain-text release verification report.

## Privacy

The application contains no server endpoint and no analytics code. ZIP contents are processed in the current browser tab.

## Browser note

The MVP uses the browser's `DecompressionStream` API for deflated ZIP entries. Very old browsers or unusual ZIP compression methods may not be supported.

## What it does NOT prove

A clean scan is not a security certification. SHA-256 verifies the bytes observed by the browser; it does not establish authorship or authenticity.

## Run

Open `index.html` in a modern browser. No build step or package installation is required.
