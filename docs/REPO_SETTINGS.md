# Repository settings checklist (owner)

These protections live in GitHub settings, not in the code, so they need the repository
owner to apply them. Tick each once set. They back the guarantees the README and
`SECURITY.md` describe (branch protection makes "every change is run through the test
suite before merge" enforceable, private reporting makes the "Report a vulnerability"
links actually reach you).

## Branch protection — `main`
- [ ] Require a pull request before merging (no direct pushes to `main`).
- [ ] Require approval from a code owner (see `.github/CODEOWNERS`).
- [ ] Require status checks to pass: **CI** (lint + tests) and **CodeQL**.
- [ ] Require branches to be up to date before merging.
- [ ] Block force pushes and branch deletion on `main`.
- Verify: Settings → Branches → Branch protection rules → `main`.

## Deploy environment — `github-pages`
- [ ] Limit the `github-pages` environment's deployment branches to `main` only.
- Verify: Settings → Environments → `github-pages` → Deployment branches.

## Security features
- [ ] Private vulnerability reporting **on** (so the "Report a vulnerability" links work).
- [ ] Dependabot alerts + security updates **on**.
- [ ] Secret scanning + push protection **on**.
- [ ] Code scanning (CodeQL) **on** (the workflow is in `.github/workflows/codeql.yml`).
- Verify: Settings → Code security and analysis.

## Account
- [ ] Two-factor authentication **on** for the owner account.
- [ ] Set the `SECURITY.md` fallback security-contact address (currently a placeholder).

## Verifying it worked
- [ ] A test pull request that fails CI or CodeQL cannot be merged.
- [ ] A test report sent through **Report a vulnerability** reaches the owner.
- [ ] `git push` straight to `main` is rejected.
