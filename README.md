# lotl-integrated-test

Test fixtures for WP4Trust: a signed EU **List of Trusted Lists (LoTL)** (ETSI TS 119 602) and the lists it points to, published from this repo's GitHub raw URLs for integration testing.

## Published lists (`dist/`)

| Path | Content |
|------|---------|
| `dist/lotl/list_of_trusted_lists-EU.json` (+ `.jws`) | LoTL pointing to the three lists below, each anchored with its signing certificate |
| `dist/pid-providers/pid_providers.json` (+ `.jws`) | LoTE of PID providers |
| `dist/pubeaa-providers/pubeaa_providers.json` (+ `.jws`) | LoTE of PubEAA providers |
| `dist/tsl/eaa-provider/trusted-list.xml` | ETSI TS 119 612 trusted list of EAA providers (XML-signed) |

All lists are signed with local **test** keys. They are not real trust anchors.

## Regenerating

The lists are built with `tsl-tool` (from [g119612](g119612/)) using the pipeline files:

```sh
./tsl-tool pipeline-pid-providers.yaml     # load + sign PID providers LoTE
./tsl-tool pipeline-pubeaa-providers.yaml  # load + sign PubEAA providers LoTE
./tsl-tool pipeline-eaa-tl.yaml            # load + sign EAA trusted list
./tsl-tool pipeline-lotl.yaml              # generate + sign the LoTL (from lote-source/lotl)
```

The first three pipelines load their sources from a local server at `http://127.0.0.1:8000`.

## Local-only files

`.gitignore` only tracks `dist/`. The pipelines, `tsl-tool`, `keys/`, `lote-source/`, `tests/eaa-mock/` (a sample go-trust evaluation request), and the `g119612` and `go-trust` checkouts exist locally but are not committed.
