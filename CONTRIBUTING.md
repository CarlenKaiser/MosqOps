# Contributing To MosqOps

Thanks for considering a contribution.

## Development Setup

1. Install Rust toolchain (stable).
2. Ensure Clang/LLVM is available for bindgen.
3. Ensure Mosquitto headers are available (or use this repository's `include/` folder via build env var).
4. Build:

   ```bash
   cargo build --release
   ```

Windows users can start with:

```bat
compile.bat
```

## Pull Request Guidelines

- Keep PRs focused and small.
- Include a clear description of behavior changes.
- Update docs when changing API behavior.
- Add tests where practical.
- Avoid unrelated formatting churn.

## Commit Messages

Use concise, action-based summaries, for example:

- `api: add client role removal endpoint`
- `docs: document dynsec reset behavior`

## Reporting Bugs

Open an issue and include:

- Expected behavior
- Actual behavior
- Repro steps
- Relevant config snippets
- Logs (with secrets removed)

## Security Issues

Do not open public issues for sensitive vulnerabilities.
Follow [SECURITY.md](SECURITY.md).
