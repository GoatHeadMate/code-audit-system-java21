# 文件操作漏洞（文件上传 + 路径遍历）判断知识

## Use When

Use this skill to validate candidate paths involving file upload, file read/write,
archive extraction, filesystem path construction, or user-controlled filenames.

## Candidate Fields That Matter

- `entryPoint`: multipart, filename, path, export/import, or archive input.
- `sink`: file read/write/copy/delete/move, archive extraction, or storage API.
- `methodPath` / `callEdges`: whether path validation happens before the sink.
- `taintConfidence` and `sourceClassification`: which path segment or filename
  is controlled.
- Nearby validation: canonicalization, root-prefix checks, extension allowlists,
  MIME/content checks, storage location, and generated server-side names.

## Common Verdict Rules

- Confirm only when source/reachability, propagation, filesystem sink/action,
  and missing or bypassed protection are visible.
- Downgrade when production profile, route reachability, trust boundary, or
  runtime storage configuration is ambiguous.
- Mark NEEDS_REVIEW when the filesystem action is sensitive but validation,
  storage root, archive handling, or runtime configuration evidence is
  incomplete.
- Suppress only when effective protection is visible and applies before the
  filesystem sink.

Effective protection must run after final path construction and before the sink,
cover the actual filename/path/archive entry, use canonical/real paths where
relevant, and remain effective after later decoding, path joins, renames,
symlink resolution, archive extraction, or dispatch indirection.

For stored or second-order candidates, confirm field correspondence: the
externally written field, DB column, mapper property, cache key, serialized
property, or config key must be the same value later read and used by the sink.
Repository/entity identity alone is supporting evidence.

## File Upload Conditions

| Condition | Verdict | Severity |
|---|---|---|
| Uploaded file type is unchecked and stored in a reachable/executable location | Confirm | HIGH |
| Only MIME type is checked | Confirm when file can influence extension/content | MEDIUM |
| Only blacklist extension filtering is used | Confirm | MEDIUM |
| Original filename is used in path construction without safe normalization | Confirm | MEDIUM/HIGH |
| File is written under web root or executable plugin/script directory | Confirm | HIGH |
| Extension allowlist, content validation, generated name, and safe storage are all present | Suppress | — |

Upload impact is higher when the target stack can execute uploaded content
directly, loads plugins/scripts from the upload directory, or later serves files
with attacker-controlled content type.

## Path Traversal Conditions

| Condition | Verdict | Severity |
|---|---|---|
| Request value directly controls filesystem path without canonical root check | Confirm | HIGH |
| `Path.normalize()` exists but no root-prefix/canonical comparison follows | Confirm | MEDIUM |
| Archive entry name is extracted without destination containment check | Confirm | HIGH |
| Blacklist filters `../` but misses encoding, Unicode, separators, or symlinks | Confirm | MEDIUM |
| `getCanonicalPath()`/`toRealPath()` plus strict root-prefix allowlist is present | Suppress | — |

Path traversal can appear in downloads, template loading, export/import, ZIP/TAR
extraction, log viewing, attachment preview, and `MultipartFile.getOriginalFilename()`.

Path traversal validation must handle Unix separators, Windows separators, drive
letters, UNC paths, absolute paths, encoded separators, double decoding, Unicode
normalization, and symlink resolution when relevant.

Archive extraction must reject absolute paths, `..` segments after
normalization, Windows drive/UNC paths, symlink entries that escape the
destination, and hardlink entries when the archive format supports them.

Canonical containment checks should happen after final path construction and
immediately before the filesystem sink. Checks performed before later path
joins, renames, symlink creation, or extraction are insufficient.

## False Positive Suppressors

Do not report when:

- Server generates the final filename and ignores attacker path components.
- Canonical/real path is checked to stay under a trusted base directory after
  normalization and symlink resolution when relevant.
- Archive extraction normalizes each entry and verifies destination containment.
- Upload storage is outside executable/web roots and retrieval enforces content
  disposition plus safe content type.
- Extension allowlist is case-insensitive and based on the final extension after
  decoding and normalization.

## Severity And Confidence

- HIGH/HIGH: attacker-controlled path reaches read/write/delete/extract sink
  without containment validation.
- HIGH/MEDIUM: upload to executable/reachable location with weak type checks.
- MEDIUM/MEDIUM: partial filename control or blacklist-only filtering.
- Suppress: generated names, strict allowlists, and canonical root checks are
  all visible.

## Evidence Requirements

A valid finding should cite:

- The user-controlled path, filename, multipart field, or archive entry.
- Path construction and validation steps.
- The filesystem sink and target directory.
- Why canonicalization, extension, content, or root checks are absent or weak.
- Suppressors considered and why they do not apply.

`rule_id` values: `upload-no-validation`, `upload-mime-only`,
`upload-web-root`, `upload-path-traversal`, `pathtrav-taint`,
`pathtrav-no-canon`, `pathtrav-zipslip`, `pathtrav-symlink`.
