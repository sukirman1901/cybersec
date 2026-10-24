# MCP runtime build diagnostics

Call the existing **`tool_health(include_optional=false)` on the connected MCP**.
The dependency fields are unchanged; runtime diagnostics are additive. No new
tools, external requests, client discovery, configuration edits, cache deletion
or reload happen during this check.

## Evidence boundaries

- `runtime`: captured once during server initialization. Contains package version,
  source fingerprint, initialization timestamp, installation/entrypoint paths,
  process PID and Python executable/version. It describes the process answering
  the call, not whichever checkout happens to be your current directory.
- `runtime.identity_kind=startup_source_snapshot`: allowlisted source files as
  observed at initialization, **not** Python bytecode/memory/dependency attestation.
  Files modified during startup or modules patched later are outside this proof.
- `files_on_disk.mcp`: a new read-only source snapshot taken at health-call time.
  `mcp_vs_startup` is `match`, `different`, or `unknown`. Source updates on disk do
  not silently replace the captured startup identity.
- `files_on_disk.plugin` and `files_on_disk.skills`: separate **current disk**
  inventories. They do not prove that the client loaded or registered those files.
  `client_plugin_state` and `client_skill_state` therefore remain `unknown`.

Local paths, Python executable and PID are diagnostic information. Redact them
before sharing externally. No environment variable values, secrets or API keys
are included in the fingerprint scope.

## Compare a live response against your checkout

Save the parsed JSON returned by the **live connected** `tool_health` call as
`health.json`. Use the tool result body, not a host-specific MCP envelope. Then:

```sh
mcp/.venv/bin/python scripts/check_runtime.py \
  --runtime-json health.json \
  --reference-root /path/to/cybersec
```

Or pass the JSON through stdin with `--runtime-json -`. Input is bounded to
1,000,000 characters. The comparison does not start or replace any MCP process.

| Status | Exit | Meaning |
|---|---|---|
| `match` | 0 | Startup source fingerprint matches reference source files |
| `different` | 1 | Complete comparable fingerprints differ |
| `unknown` | 2 | Old/missing/invalid identity, missing/unreadable sources, incompatible schema/scope, or invalid JSON |

An older MCP without the new runtime fields must produce `unknown`, not match.
Package version `1.0.0` or a count of 209 tools alone cannot distinguish builds.
Snapshots are self-reported, not cryptographically authenticated attestations.
A previously saved response cannot prove the server is still the same process.

If different or unknown, inspect the reported server installation and your
client's selected MCP installation, then use the client's own reload/reconnect
feature if appropriate. Run `tool_health` again on the connected server and
compare the new response. This tool deliberately does not change client state.
Starting a **fresh test subprocess** only tests that new subprocess; it does not
verify the identity of an existing MCP connected to your agent.

## Fingerprint scope and stability

`sha256-source-v1` hashes a canonical sorted list of relative paths and SHA-256
file hashes. Install paths, timestamps and git history are not part of the digest,
so identical source packages compare consistently in different directories and
without a `.git` folder.

- MCP scope: `package.json`, `mcp/requirements.txt`, `mcp/server.py` and recursive
  `mcp/cyber_tools/*.py` sources.
- Plugin disk scope: `.opencode/plugins/cybersec.js` only; this is not an inventory
  of every client integration or its settings.
- Skill disk scope: `skills/*/SKILL.md` only; referenced resources are not attested.
- Excluded: virtualenvs, Python bytecode, tests, logs, `.env`, client config,
  unrelated workspace files and dependency contents.

Missing required files, unreadable/oversized files, or source symlinks escaping
the package produce incomplete evidence, hence `unknown`. Hashing is not an
atomic filesystem snapshot; retry after concurrent updates finish. A matching
source digest does not guarantee the same installed dependencies or runtime
behavior. New source files under the MCP scope change the fingerprint too.
