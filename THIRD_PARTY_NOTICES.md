# Third-party notices

This project incorporates adapted implementation ideas and portions from:

1. **stormzhang/ipcheck** — https://github.com/stormzhang/ipcheck
   - Reviewed commit: `50018243a5699df10c6b46617f3fe4bd73b35dab`.
   - The root license is Apache License 2.0; preserved in `licenses/stormzhang-ipcheck-Apache-2.0.txt`.
   - Its package metadata and README identify MIT instead. This inconsistency is recorded; this project preserves the root license rather than relabelling the upstream work.
   - Adapted proxy parsing and diagnostic structure. Modified files and behavior are documented in `docs/upstream-sources.md`.

2. **yacuo/check-cc** — https://github.com/yacuo/check-cc
   - Reviewed commit: `078e7baa1d2a08df28da3f25dacb90e687f4c79f`.
   - Copyright (c) 2026 yacuo / CheckCC.
   - MIT License, preserved in `licenses/yacuo-check-cc-MIT.txt`.
   - Browser sampling and limited font-width comparison were adapted in earlier revisions. Protocol 1.1 removed the local web UI and all browser sampling, so none of that code remains in the current version. The original risk scoring and public-site design are not included.

Modified and newly written project code is distributed under Apache License 2.0. The above third-party notices and applicable license terms remain in effect.
