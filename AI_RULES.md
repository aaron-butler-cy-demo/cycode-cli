# AI Coding Rules for cycode-cli

This file guides AI coding assistants generating or modifying code in this repository. Every rule is grounded in the repository's actual structure, active security findings, or confirmed coding conventions. Rules use **MUST/NEVER/ALWAYS** for requirements derived from findings or confirmed conventions, and **SHOULD/PREFER/CONSIDER** for hardening guidance.

---

## Project Overview

`cycode-cli` is a Python CLI application (Python ≥ 3.9) built with Typer and Click, packaged via Poetry, and distributed as a Docker container and standalone executable. It scans source code for secrets, SCA vulnerabilities, IaC misconfigurations, and SAST issues. It also exposes a Model Context Protocol (MCP) server for AI agent integration. The main package is `cycode/`, tests live in `tests/`, and CI/CD pipelines are defined in `.github/workflows/`.

---

## Highest-Priority Repo-Editable Security Rules

### Dependency Vulnerabilities in `pyproject.toml` and `poetry.lock`

- **NEVER** widen the `urllib3` version range to include `>=2.6.0`. The current constraint `urllib3 = ">=2.4.0,<3.0.0"` permits the High-severity CVE-2026-44431 (sensitive `Authorization` headers forwarded to a different host during proxied redirects). Tighten the upper bound to exclude the vulnerable resolved version until a patched release is confirmed.
- **NEVER** allow `marshmallow` to resolve to `4.0.1`. CVE-2025-68480 enables a denial-of-service via `Schema.load`. When raising the lower bound, update `poetry.lock` to confirm the resolved version is non-vulnerable.
- **NEVER** allow `requests` to resolve to `2.32.5`. CVE-2026-25645 causes insecure temporary file reuse in `extract_zipped_paths()`. Tighten the range floor once a patched version is available.
- **NEVER** allow `pytest` to resolve to `8.4.2`. CVE-2025-71176 involves vulnerable `tmpdir` handling. Raise the lower bound past the patched version.
- **NEVER** introduce or pin `setuptools` to `82.0.1`. CVE-2026-59890 allows `MANIFEST.in` exclusion bypass via Unicode normalization on macOS. This is a transitive dependency — do not add it as a direct dependency at this version.
- **ALWAYS** update `poetry.lock` when changing any version constraint in `pyproject.toml`. The lock file is the source of truth for reproducible builds.
- WHEN editing `pyproject.toml`, preserve the existing tight minor-range pinning style (e.g., `>=X.Y.Z,<X.Y+1.0`) for security-sensitive packages. Do not loosen tight ranges to wide major-cap ranges (e.g., `<3.0`) for packages with known CVEs in the permitted range.
- Do NOT change exact pins (`patch-ng = "1.19.1"`, `ruff = "0.15.20"`) to ranges without explicit justification.
- Do NOT use caret (`^`) pinning for new security-sensitive packages. The existing `typer = "^0.15.3"` is a confirmed convention; do not extend this pattern to packages that handle network I/O, authentication, or serialization.

### License Compliance

- **NEVER** add packages with non-permissive licenses (GPL, AGPL, MPL) to the `[tool.poetry.dependencies]` group without explicit legal review. `certifi` (MPL-2.0) and `pyinstaller` (GPL-adjacent) are intentionally confined to specific dependency groups — do not promote them to core dependencies.
- Keep `pyinstaller` isolated in `[tool.poetry.group.executable.dependencies]`. Do not add it to any other group.

---

## Secrets and Credentials Rules

- **NEVER** hardcode real API keys, tokens, passwords, or credentials anywhere in the codebase — including source files, configuration files, test fixtures, or documentation.
- **NEVER** change the fake credentials in `tests/conftest.py` to real values. The variables `_EXPECTED_API_TOKEN`, `_CLIENT_ID`, `_CLIENT_SECRET`, and `_ID_TOKEN` must remain as non-functional placeholders. They are explicitly commented as fake.
- **NEVER** add new test fixture files containing real-format secrets (Slack tokens, AWS keys, GitHub PATs, etc.) even if the values appear fake. Use clearly invalid placeholder strings instead. The existing `tests/test_files/zip_content/secrets.py` contains an intentional fake Slack token for secret-detection testing — do not replace it with a real token.
- Credentials are loaded at runtime from environment variables (`CYCODE_CLIENT_ID`, `CYCODE_CLIENT_SECRET`, `CYCODE_ID_TOKEN`) or from `~/.cycode/credentials.yaml`. Do not add any code path that reads credentials from source files, hardcoded strings, or committed config files.
- WHEN adding new credential fields to `CredentialsManager`, follow the existing pattern: check environment variables first, fall back to `~/.cycode/credentials.yaml`, and never store values in plaintext within source code.

---

## Authentication Rules

- **NEVER** bypass the PKCE (Proof Key for Code Exchange) device flow by hardcoding `code_verifier` or `code_challenge` values. These must be cryptographically generated per session in `cycode/cyclient/auth_client.py`.
- **NEVER** store `client_secret`, `id_token`, `api_token`, or `access_token` values in plaintext within source code. The auth flow retrieves tokens at runtime.
- WHEN modifying `parse_api_token_polling_response` in `auth_client.py`, do not widen the bare `except Exception: return None` pattern to suppress additional security-relevant failures silently.
- WHEN passing data to `marshmallow` schemas used in auth response parsing (e.g., `AuthenticationSessionSchema`, `ApiTokenGenerationPollingResponseSchema`), do not pass unvalidated, unbounded external input directly to `Schema.load` until `marshmallow` is confirmed patched above the CVE-2025-68480 vulnerable version.

---

## HTTP Client Rules

- **NEVER** set `verify=False` on any `requests` call or session. No instance of `verify=False` exists in production code — this must remain the case.
- **NEVER** remove the `timeout=self.timeout` parameter from HTTP requests in `CycodeClientBase`. All requests must pass a timeout derived from `config.timeout` to prevent indefinite hangs.
- **NEVER** hardcode timeout values at individual call sites. Timeouts must flow from `config.timeout` to allow operator configuration. Per-request overrides via the `timeout=` kwarg in `_execute` are acceptable.
- **NEVER** create ad-hoc `requests.Session` instances. All HTTP calls must go through the shared `_get_session()` singleton defined in `cycode/cyclient/cycode_client_base.py`, which manages connection pooling and the system trust store.
- **NEVER** call `requests` methods directly from outside `CycodeClientBase` subclasses. All HTTP calls must go through `CycodeClientBase.post()`, `CycodeClientBase.get()`, `CycodeClientBase.put()`, or `CycodeClientBase.post_multipart()`.
- Do NOT disable the `truststore` integration. The OS trust store (`truststore` package) is the preferred CA source on Python ≥ 3.10. The Windows `SystemStorageSslContext` fallback is intentional — do not remove it.
- Do NOT set `Authorization` headers at the `urllib3` session level. Due to CVE-2026-44431, `urllib3` can forward sensitive headers to a different host during proxied redirects. Set authorization headers per-request or rely on the existing `CycodeClientBase` header management.
- WHEN adding new HTTP methods or retry logic, preserve the existing `@retry` decorator pattern from `tenacity` with `stop_after_attempt(3)` and `wait_random_exponential(multiplier=1, min=2, max=10)`. Do not remove `reraise=True` or the `before_sleep` logging callback.
- WHEN adding new mandatory headers, add them to `CycodeClientBase.MANDATORY_HEADERS` so they are applied to all requests automatically.

---

## Container and Dockerfile Rules

- **MUST** include a `HEALTHCHECK` instruction in the `final` stage of the `Dockerfile`. The current `Dockerfile` is missing this instruction (IaC finding). Add it before the `USER` directive. A suitable form is:
  ```dockerfile
  HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD cycode --help > /dev/null 2>&1 || exit 1
  ```
- **NEVER** remove the `USER cycode` directive from the `final` stage. The container must run as the non-root user `cycode` (UID 5001, GID 5000). Any change that runs the container as root is a violation.
- **NEVER** use unpinned or floating base image tags. The current `python:3.12.9-alpine3.21` and `git=2.47.3-r0` are correctly pinned. Do not change these to `latest` or unversioned tags.
- **NEVER** copy the `.git` directory into the `final` stage. It is present in the `builder` stage only for version detection via `poetry-dynamic-versioning`. Ensure `COPY --from=builder` never includes `.git`.
- WHEN adding new `RUN` instructions in the `builder` stage, follow the existing pattern: install build dependencies, perform the build, and remove build dependencies in the same `RUN` layer to minimize image size.
- WHEN adding new `COPY` instructions, copy only the specific files needed. Do not use `COPY . .`.
- Keep `--no-cache-dir` on all `pip install` calls and `--no-cache` on `poetry install` calls, consistent with the existing Dockerfile.

---

## CI/CD Workflow Rules

- **NEVER** hardcode registry credentials, tokens, or secrets directly in workflow YAML files. Use GitHub Actions secrets via `${{ secrets.* }}`.
- **NEVER** disable or remove the Cimon runtime security monitor step (`cycodelabs/cimon-action`) from workflow files. It enforces network egress restrictions with `prevent: true` and an `allowed-hosts` allowlist.
- **ALWAYS** pin GitHub Actions references to a full commit SHA with a version comment (e.g., `actions/checkout@<sha> # v7.0.1`). Do not use floating tags such as `@v3` or `@main`.
- Do NOT disable or remove the `ruff.yml` linting workflow. It enforces code quality gates including security-relevant rules from the `S` (bandit) ruleset.
- Do NOT add `--no-verify` flags or skip steps in `tests.yml` or `tests_full.yml`. All test gates must pass.
- Do NOT modify `.github/dependabot.yml` to increase update intervals beyond weekly or to ignore security updates for packages with active CVEs.
- WHEN adding new workflow steps that require network access, add the required hosts to the `allowed-hosts` list in the Cimon step rather than disabling Cimon.
- WHEN editing workflow files, preserve `permissions: contents: read` (minimal GitHub token scope) unless a specific step requires elevated permissions, in which case scope the elevated permission to that job only.

---

## Dependency and Supply Chain Rules

- WHEN adding a new runtime dependency to `[tool.poetry.dependencies]`, use a tight minor-version range (e.g., `>=X.Y.Z,<X.Y+1.0`) consistent with the existing style for most packages. Avoid open-ended upper bounds for packages that handle network I/O, authentication, or serialization.
- WHEN adding a new dependency that is only needed for Python ≥ 3.10, use the `markers = "python_version >= '3.10'"` pattern, consistent with `mcp` and `truststore`.
- WHEN adding a Windows-only dependency, use the `markers = "python_version >= '3.10' and sys_platform == 'win32'"` pattern, consistent with `pywin32`.
- WHEN adding a Python version-conditional stdlib backport (e.g., a `tomllib` equivalent), use the `python = "<3.X"` constraint pattern, consistent with `tomli`.
- Do NOT add MCP-related dependencies outside the `python_version >= '3.10'` marker. MCP support is intentionally gated to Python 3.10+.

---

## CLI Command and Code Style Rules

- **ALWAYS** use absolute imports. Relative imports are banned by the ruff `TID252` rule (`ban-relative-imports = "all"`).
- **ALWAYS** provide type annotations on all new functions. The `ANN` ruleset is enabled. `*args` and `**kwargs` annotations and `typing.Any` are explicitly allowed.
- Use single quotes for inline strings and double quotes for docstrings and multiline strings, consistent with the ruff quote configuration.
- Maximum line length is 120 characters (`line-length = 120` in ruff config).
- WHEN adding a new CLI subcommand, register it in `_SUBAPP_MODULES` in `cycode/cli/app.py` using the lazy-loading pattern (`importlib.import_module`). Do not import subcommand modules at the top level of `app.py`.
- WHEN defining new CLI options, use the `Annotated[Type, typer.Option(...)]` style with both short and long flags (e.g., `-t`/`--transport`), `case_sensitive=False` for enum options, and always specify a default value.
- WHEN adding a new subcommand that emits JSON output (e.g., for AI agent consumption), suppress the version-update notifier for that command by adding it to the skip condition in `check_latest_version_on_close`.
- WHEN handling exceptions in CLI command functions, log with `exc_info=e` and re-raise as `typer.Exit(1) from e`. Do not swallow exceptions silently.
- Do NOT set `pretty_exceptions_show_locals=True` on the Typer app. Local variable leakage in tracebacks is intentionally disabled.
- WHEN adding output to CLI commands, support both `OutputTypeOption.RICH` (default, Rich markup) and `OutputTypeOption.JSON` modes. Check `ctx.obj['output']` to determine the active mode.

---

## MCP Server Rules

- **ALWAYS** sanitize file paths passed to MCP scan tools using `pathvalidate.sanitize_filepath()` before any filesystem operation, consistent with `_sanitize_file_path` in `cycode/cli/apps/mcp/mcp_command.py`.
- **ALWAYS** verify that a sanitized path remains within the intended temporary directory using `os.path.normpath` comparison before writing files, consistent with the `_TempFilesManager.__enter__` boundary check.
- **ALWAYS** clean up temporary directories created for file-based scans using `shutil.rmtree` in the context manager `__exit__`, consistent with `_TempFilesManager`.
- WHEN adding new MCP tools, expose them via `Tool.from_function()` in `_create_mcp_server` and accept both `paths: Optional[list[str]]` and `files: Optional[dict[str, str]]` parameters using the `_PATHS_TOOL_FIELD` and `_FILES_TOOL_FIELD` Pydantic field definitions.
- WHEN adding new MCP tools, run scans by spawning a subprocess via `_run_cycode_command` rather than calling scan logic directly. This preserves process isolation.
- Gate MCP imports with `try/except ImportError` and raise a clear error message when Python < 3.10, consistent with the existing pattern in `mcp_command.py`.
- Do NOT bind the MCP SSE/HTTP server to `0.0.0.0` by default. The default host is `127.0.0.1`. Only change this if the user explicitly passes `--host`.

---

## Testing Rules

- **NEVER** use real credentials, API keys, or tokens in test fixtures. All credential-like strings in `tests/conftest.py` are intentionally fake and explicitly commented as such.
- **NEVER** remove `pyfakefs` from `[tool.poetry.group.test.dependencies]`. It provides filesystem isolation critical for tests involving file I/O.
- Test files MUST follow the `test_*.py` naming convention. Directory structure under `tests/` mirrors the source structure under `cycode/`.
- WHEN adding new tests, use `pytest-mock` (`mocker` fixture) for mocking and `responses` for HTTP mocking, consistent with the existing test suite.
- WHEN writing tests that involve filesystem operations, use `pyfakefs` to avoid writing to real paths.
- `log_cli = true` is set in `[tool.pytest.ini_options]` — do not remove it.
- The `S101` (assert) and `S105` (hardcoded password) ruff rules are suppressed for `tests/*.py` — this is intentional. Do not add `# noqa` overrides for these rules in source files.

---

## Prohibited Repo Patterns

- `verify=False` on any `requests` call or session
- Hardcoded credentials, tokens, API keys, or secrets in any source, config, or test file
- Relative imports anywhere in `cycode/` or `tests/`
- Direct `requests.Session()` instantiation outside `_get_session()` in `cycode/cyclient/cycode_client_base.py`
- Direct `requests.get/post/put` calls outside `CycodeClientBase` subclasses
- `USER root` or removal of `USER cycode` in the `Dockerfile` `final` stage
- Floating or `latest` base image tags in the `Dockerfile`
- Hardcoded secrets or credentials in `.github/workflows/` YAML files
- Floating GitHub Actions tags (e.g., `@v3`, `@main`) — all action refs must be pinned to a full commit SHA
- `pyinstaller` or any GPL/AGPL-licensed package added to `[tool.poetry.dependencies]`
- `urllib3` version constraints that permit `>=2.6.0` while CVE-2026-44431 is unpatched
- `marshmallow` version constraints that permit `4.0.1` while CVE-2025-68480 is unpatched
- Unsanitized file paths passed to filesystem operations in MCP tool handlers
- MCP server bound to `0.0.0.0` as a default
- `pretty_exceptions_show_locals=True` on the Typer app
