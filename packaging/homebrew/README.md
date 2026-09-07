# Homebrew offline-readiness inputs

`modules.json` and `homebrewcheck` cover dependency-closure and offline
source-build readiness only. They do not establish readiness for a Formula or
Cask, signing, native Gate evidence, or publication. The accepted future
distribution uses an immutable signed app delivered by Cask; it does not
rebuild the approval helper from source.

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
