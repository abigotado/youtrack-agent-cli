# Homebrew offline-readiness inputs

`modules.json` is the canonical dependency manifest for a future source-built
Homebrew formula. It is not a Formula, renderer, or publication mechanism.

The manifest must match the complete `require` closure in `go.mod`. Each digest
is for the corresponding Go proxy `.zip`, not for a VCS or GitHub archive.
`homebrewcheck` rejects replacements and validates both `go.sum` entries before
it accepts a module.

Stage downloads with the standard Go proxy layout:

```text
<proxy-dir>/<module-path>/@v/<version>.zip
```

Then run the network-free readiness check:

```bash
go run ./tools/homebrewcheck --proxy-dir <proxy-dir>
```

Add `--build` to rehearse the source build. The checker creates a disposable
source tree, derives `vendor/` and `vendor/modules.txt` from the verified proxy
zips, and builds with empty caches, `CGO_ENABLED=1`, `GOPROXY=off`,
`GOSUMDB=off`, and `GOTOOLCHAIN=local`. It does not contact YouTrack or the
Keychain.
