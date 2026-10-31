# Project journal

The active rust-gvm project journal is maintained on the dedicated
[`journal-main` branch](https://github.com/greenbone-hive/rust-gvm/tree/journal-main/journal).

This directory on `main` is intentionally pointer-only. Keeping journal-only
updates on `journal-main` avoids adding operational history to the source and
release branch while preserving the complete journal in Git.

Journal updates use a `journal/YYYY-MM-DD` branch, change the corresponding
`journal/YYYY-MM-DD.md` entry, and open a pull request targeting `journal-main`.
