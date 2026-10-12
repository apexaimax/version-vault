# Browser memory safety plan (draft, 2026-10-12)

## Evidence and current risk
- `parseZip(file)` rejects files over 1 GiB before `arrayBuffer()`, but then reads the entire archive into RAM.
- Stored entries use `slice()` copies; deflated entries accumulate chunks then allocate and copy a contiguous output buffer. Parsed results retain extracted entry data and SHA/CRC metadata.
- Comparing two archives can retain both parsed maps at once. The 512 MiB per-archive uncompressed limit is **not** a process-memory cap.
- CI regression tests cover oversized input rejection, bounded decompression, malformed ZIP64 and excessive entry counts; no iPad peak-memory benchmark has been run.

## Proposed design (do not implement without regression tests)
1. **Index first**: read bounded tail to locate EOCD/ZIP64; read and validate bounded central-directory ranges using `Blob.slice().arrayBuffer()` rather than whole-file `arrayBuffer()`. Validate integer arithmetic, offsets, overlapping regions, entry count, duplicate names, local headers and compression method.
2. **Process entries sequentially**: slice each compressed entry only when needed. Stream decompression with per-entry and cumulative byte accounting, and compute CRC32/SHA-256. Browser WebCrypto SHA-256 is non-streaming; either use a reviewed incremental implementation or keep a bounded per-entry buffer until hashing. Do not claim streaming memory safety while retaining all extracted data.
3. **Retain metadata by default**: store filename, size, CRC32, SHA256, flags and small explicitly bounded previews. Review downstream security heuristics, manifest/package inspection, and report generation before removing full `data` retention; preserve feature parity with focused tests.
4. **Avoid simultaneous archive retention**: process old/new sequentially and retain compact metadata. Explicitly release large buffers and cancel streams on error. Avoid unsafe assumptions about garbage-collection timing.
5. **Limit and UX policy**: keep current conservative caps until browser measurements justify changing them; show an actionable error when limits or browser resources are exceeded.

## Required gates
- Red/green tests: no whole-archive read; tail/central-dir truncation and malicious offsets; local/central mismatch; ZIP64; duplicate paths; stored and deflated entries; CRC/hash parity; decompression bomb; cumulative budget; cancellation/error cleanup.
- Feature parity: diff counts, sensitive filename/content heuristics, extension manifest permissions, package metadata, downloadable report, existing fixture and sample ZIPs.
- Browser: desktop Chromium and Safari/iPad on synthetic ZIPs at increasing sizes; record peak memory where instrumentation permits, completion/failure and UI responsiveness. Do not infer iPad memory from Node CI.
- Privacy: live network inspection on deployed origin with sample files, no filenames/content leaving device; inspect third-party assets and tracking.
- Licensing/accessibility: dependency and provenance inventory; license decision; keyboard, focus, contrast and screen-reader checks.

## Approval boundary
Draft plan only. Work stays on PR #12; do not merge or publish a new release without explicit final approval.
