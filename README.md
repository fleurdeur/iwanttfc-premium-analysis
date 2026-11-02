# iwant_bypass

Single-file iWantTFC capture / grab / mint / replay / player tool plus an offline
test + analysis suite. No user data is committed.

## Bring your own

Put your own account data in the working folder before use:

- bearer token: `token_template.json` -> `token.txt` (run `python iwant_bypass.py token`)
- identity: `identity_template.json` -> `identity.json` (run `python iwant_bypass.py ident`)
- start templates / captured sessions: `start_template.json`, `sessions/`

## Commands

- `chrome`, `login`, `token`, `ident`, `grab`, `routes`, `capture`
- `mint`, `replay`, `plan`, `selftest --live`, `doctor`
- `play` -> local DASH / Widevine player

## Notes

- Entitled content only. Premium titles return EPS 401; not supported.
- Widevine needs a real CDM; attach your own Chrome over CDP.

## Web tester

The stream tester is published on GitHub Pages: https://fleurdeur.github.io/iwanttfc-premium-analysis/

The source lives in `dash_tester.html` in this repo (also at the repo root copy).

## Tests

- `python -m unittest test_iwant_bypass -v`
- `python iwant_bypass.py selftest`
- `python iwant_bypass.py selftest --live`
