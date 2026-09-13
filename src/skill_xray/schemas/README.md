# SARIF schema

`sarif-schema-2.1.0.json` is the unmodified OASIS SARIF 2.1.0 Errata 01
operating schema. `dev/prepare_sarif_schema.py` pins its official URL and SHA-256.
The verified asset is generated locally and included in wheels/source distributions,
not tracked in Git. Source builds fail if it is missing or differs from the pin.
Run `python dev/prepare_sarif_schema.py` before an editable install or source build;
`--cache /path/to/schema.json` supports offline preparation. Cache contents are verified
on use. Missing caches may be fetched only by this explicit preparation command.
Preparation directories must be trusted against concurrent replacement.
All schema references are local; runtime validation never downloads a schema.

Copyright and usage terms are provided by the OASIS SARIF specification:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html
