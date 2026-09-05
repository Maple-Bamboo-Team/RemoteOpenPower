# Project Engineering Rules

These rules apply to every source, test, build, and documentation change in this repository.

## Completion Gate

- Do not ignore compiler warnings, Clippy findings, test failures, I/O errors, or failed cleanup. Fix the owning design or propagate the error with useful context.
- Do not use `allow` attributes, dummy reads, empty branches, or disabled code as a way to silence a warning.
- Before completion, run formatting, all-target tests, Clippy with `-D warnings`, and a Linux cross-build. A change is incomplete if any supported target does not compile.
- Keep Cargo cache, rustup data, and temporary build files under `E:\Catch\Cargo`; keep final artifacts under this repository's `target` directory.

## Design Consistency

- Each concept has one meaning and one source of truth. Authentication IDs, display labels, limits, defaults, paths, and timeouts must not be reused for different purposes.
- UI validation, serialized configuration validation, protocol validation, and runtime enforcement must accept and reject the same values. Prefer a shared validator or a compile-time/test invariant over copied constants.
- Deployment instructions must be executable on the platform that displays them and must match runtime path, owner, group, mode, and environment requirements.
- Platform-specific work belongs behind the correct `cfg` boundary. Windows must not execute or display Linux deployment steps, and Linux must not depend on Windows behavior.
- Preview/demo state stays outside production runtime code. Production status must come from configuration or live events, never fake rows or hard-coded success.

## Root-Cause Changes

- Fix the model or ownership boundary that caused a bug. Do not accumulate call-site exceptions for a contradictory model.
- Do not preserve obsolete configuration or protocol behavior unless compatibility is an explicit requirement. Remove dead compatibility paths and update tests and documentation together.
- Sensitive files must use fail-closed, handle-based reads and atomic private writes. Linux supports owner-private files and `root:<service-group>` read-only service configuration; saves must preserve a safe deployed owner/group policy.
- A destructive action must validate the exact target and identity first. Report a failed deletion or replacement; never present partial completion as full success.
