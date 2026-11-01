# Repository settings checklist (owner)

These protections live in GitHub settings, not in the code, so they need the repository
owner to apply them. They back the guarantees the README and `SECURITY.md` describe
(branch protection makes "every change is run through the test suite before merge"
enforceable, private reporting makes the "Report a vulnerability" links reach you).

Ticked items were read back from GitHub on 31 October 2026. Check this list again after
any change to who has access, and at each quarterly review.

## Branch protection — `main` (Settings → Rules → Rulesets → "protect main")
- [x] Require a pull request before merging (no direct pushes to `main`).
- [x] Block force pushes and branch deletion on `main`.
- [x] Require linear history and signed commits (merges made on GitHub are signed by GitHub).
- [ ] Require status checks to pass: add **`test`** (CI) and **`analyze`** (CodeQL), source
      GitHub Actions. The rule exists but its list of checks is empty, so nothing is enforced yet.
      Don't add `check` (Website): it runs only when the site changes, and a required check that
      never runs blocks every other pull request.
- [ ] Require branches to be up to date before merging (the same rule's "strict" option).
- [ ] Code-owner approval: leave **off** while you are the only maintainer and the maintaining
      Claude instances open pull requests under your account — GitHub never lets an author
      approve their own pull request, so it would block every merge. Review each pull request
      yourself before you press Merge instead.

## Deploy environments
- [ ] `github-pages`: Settings → Environments → `github-pages` → Deployment branches: `main` only.
- [ ] `release` (create it by hand before the first release, or the first run creates it unprotected):
      Required reviewers: you; Deployment branches and tags: `main` and tags matching `v*` (`main` is
      needed for Actions → Release → Run workflow → Publish, which creates the tag itself).
- [ ] `pypi` (used by the release workflow's PyPI upload): Deployment branches and tags: `main` and tags
      matching `v*`, so a workflow run from any other branch can't use the PyPI publisher. Required
      reviewers are optional: the `release` approval comes first.

## Security features (Settings → Code security)
- [x] Private vulnerability reporting **on** (so the "Report a vulnerability" links work).
- [x] Dependabot security updates **on** (alerts are on with them).
- [x] Secret scanning + push protection **on**.
- [x] Code scanning (CodeQL) **on** (the workflow is in `.github/workflows/codeql.yml`).

## Account
- [ ] Two-factor authentication **on** for the owner account, with a security key or passkey.
- [x] `SECURITY.md` fallback contact: no address needed; people without private reporting open an
      issue titled "Security contact request" and get a private channel.
- [ ] Claim the name `foldward` on PyPI through trusted publishing (see `docs/NAME_CLEARANCE.md`):
      pypi.org → Your account → Publishing → add a pending publisher: project `foldward`, owner
      `dylanckoldan-boop`, repository `foldward`, workflow `release.yml`, environment `pypi`. The next
      release uploads the package and the name is yours.

## Verifying it worked
- [ ] A test pull request that fails CI or CodeQL cannot be merged.
- [ ] A test report sent through **Report a vulnerability** reaches the owner.
- [ ] `git push` straight to `main` is rejected.
