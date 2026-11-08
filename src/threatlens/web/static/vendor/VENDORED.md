# Vendored front-end assets

ThreatLens never loads anything from a CDN at runtime. Third-party assets are
copied here verbatim from the official npm tarballs (tarball `integrity`
verified against the npm registry, files compared byte-for-byte).

| Package | Version | Files | SHA-256 | License |
|---|---|---|---|---|
| htmx.org | 2.0.11 | `htmx/htmx.min.js` | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` | 0BSD (`htmx/LICENSE`) |
| swagger-ui-dist | 5.34.0 | `swagger-ui/swagger-ui-bundle.js` | `3f6abf70480db7e07914df4c98a77385f22ea585eaf457a3e6415ba0eae2d167` | Apache-2.0 (`swagger-ui/LICENSE`) |
| swagger-ui-dist | 5.34.0 | `swagger-ui/swagger-ui.css` | `c3cfe8248c4b0b89673600fb829924eafbac6de4bc4b2b06f5f5243483074d0a` | Apache-2.0 |
| uplot | 1.6.32 | `uplot/uPlot.iife.min.js` | `19c8d4c6ad88929a79f4ae49d6f7161566dfd0ba3d15cc495e974f787eb78f1f` | MIT (`uplot/LICENSE`) |
| uplot | 1.6.32 | `uplot/uPlot.min.css` | `df630c6a8d6f8eeaff264b50f73ce5b114f646ffd9a0bb74f049b0a00135fa04` | MIT |

To update: download the new tarball from `https://registry.npmjs.org/<pkg>/-/<pkg>-<version>.tgz`,
check its `integrity` field, copy the files, and update this table and the test
`tests/test_vendored_assets.py`.
