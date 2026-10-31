# Claims → code → test

Every public capability sentence on the website, in the README and in the docs maps to
the source that implements it and the test that proves it — or is marked **planned** when
it is design intent that isn't wired yet. This table is the anti-drift record: when a claim
changes, its row changes with it, and new PRs add "claims updated" to the checklist.

Paths are relative to the repository root. "Test" names a file in `tests/`.

## Implemented — claim, code, test

| Public claim | Implemented in | Proven by |
|---|---|---|
| Agents you sanction carry a signed, least-privilege identity (scope of actions, hosts, path prefixes), checked against the revocation registry. | `identity.py` (`Scope`, `Credential`, `TrustDomain`) | `test_identity.py` |
| An unregistered agent is flagged (score ≈ 35), not blocked or hidden. | `detect.py` (`score_agent`) | `test_detect.py::test_unregistered_agent_gets_an_identity_reason` |
| Identity is decided by PID + creation time or a verified path, never by text the process controls (command line). | `detect.py` (`Detector.detect`, `looks_like_agent`) | `test_audit_regressions.py::test_foldward_marker_does_not_hide_an_agent`, `::test_system_agents_are_not_ai_agents` |
| A planted decoy is a near-zero-false-positive intrusion signal, trips during a live scan, and only the bait itself trips it. | `tripwire.py` (`is_canary` marker), `core.py` (`_note_canary_contact`) | `test_audit_regressions.py::test_canary_contact_trips_during_a_normal_scan`, `test_tripwire.py` |
| Pacify is graduated, reversible-first containment (throttle → quarantine → revoke → suspend → terminate), on resources you own, defaulting to suspend. | `response.py` (`Response.pacify`, `Rung`) | `test_response.py`, `test_audit_regressions.py::test_automatic_containment_never_grows` |
| Quarantine **moves** the agent's artifact into an encrypted (AES-256-GCM) store and can restore it byte-for-byte; the script is taken, never the shared interpreter. | `quarantine.py` (`add`/`restore`), `core.py` (`_quarantine_target`) | `test_quarantine.py`, `test_audit_regressions.py::test_own_quarantine_moves_the_file`, `::test_interpreter_is_never_quarantined` |
| Containment acts only on the process that was flagged — a reused PID is refused. | `response.py` (`Containment._resolve`) | `test_audit_regressions.py::test_pacify_refuses_a_reused_pid` |
| A suspended agent that is resumed is re-frozen on the next scan and the tamper is logged/alerted. | `core.py` (`_recheck_suspended`) | `test_audit_regressions.py::test_resumed_agent_is_suspended_again` |
| A flag contains only after an in-process quorum agrees; a decoy touch is self-authorizing. | `mesh.py` (`Consensus`) | `test_mesh.py`, `test_core.py` |
| Every step lands in a hash-chained, tamper-evident audit whose head can be PQ-signed; it breaks under tampering. | `crypto.py` (`AuditLog`) | `test_crypto.py`, `test_core.py::test_snapshot_reports_a_broken_audit_chain` |
| A revocation is accepted only with a valid circle signature; a credential signature can't be replayed as a revocation. | `registry.py`, `identity.py` (`_canonical`) | `test_registry.py`, `test_audit_regressions.py::test_signed_messages_are_unambiguous` |
| Signing is hybrid ML-DSA-65 + Ed25519; `auto` never silently downgrades to the symmetric HMAC fallback. | `crypto.py` (`HybridSigner`, `new_signer`) | `test_crypto.py`, `test_audit_regressions.py::test_auto_signer_never_falls_back_to_hmac` |
| The keypair, audit, revocations and registrations persist across a restart. | `crypto.py`, `registry.py`, `core.py` (`_load_agents`/`_save_agents`) | `test_audit_regressions.py::test_state_survives_a_restart` |
| Locality is judged with `ipaddress` (RFC1918/ULA/link-local only); public 172.x and CGNAT are not local. | `detect.py` (`_is_local`) | `test_audit_regressions.py::test_public_172_addresses_are_not_local`, `::test_link_local_and_unique_local_addresses_are_local` |
| Settings are type/range validated and the detection lists can't be emptied to blind the net. | `config.py` (`_validated_kwargs`) | `test_audit_regressions.py::test_settings_with_wrong_types_fall_back_to_defaults`, `::test_settings_cannot_empty_the_detection_lists` |
| sentinel-vision's CLI is resolved only from canonical install dirs, never `$PATH`. | `integrations/sentinel_vision.py` (`_resolve_cli`) | `test_audit_regressions.py::test_sentinel_vision_cli_is_not_taken_from_path`, `test_integrations.py` |
| Foldward runs with no partners installed; everything degrades to its own mechanisms, never an error. | `integrations/` (`partner_status`, `make_containment`) | `test_integrations.py` |
| The website sets a CSP + referrer policy and uses no inline styles; light-mode link contrast meets WCAG AA; install commands fetch from the repo, not the unrelated PyPI package. | `site/*.html`, `site/style.css`, `README.md`, `docs/*.md` | `test_audit_regressions.py::test_site_pages_have_a_content_security_policy_and_no_inline_styles`, `::test_light_mode_link_contrast_is_at_least_4_5`, `::test_install_commands_never_fetch_the_unrelated_pypi_package` |
| Foldward contains no AI model. Its core — detection, scoring, containment, the audit — opens no network connection and sends no telemetry. The *only* network use anywhere is the opt-in update check, which you trigger explicitly. | core modules in `src/foldward/` (no network imports); network isolated to `src/foldward/update.py` | `test_update.py` (the check is explicit, injectable and degrades gracefully); core verified by inspection |

## Planned / design prototype — do not read as shipped

| Claim as design intent | Status |
|---|---|
| "Cut egress" as an automatic pacify rung. | **Planned.** `block_egress` exists as a containment hook (real when sentinel-vision is present); the ladder does not climb to it automatically. |
| sentinel-vision `scan` gives a verdict used in the decision. | **Planned.** `SentinelVisionAdapter.scan` exists but is not invoked by the core scan loop. |
| The "many doors" mix channel hides oversight traffic on the wire. | **Design prototype.** `MixChannel` emits fixed-size, CSPRNG, unlabeled cover records (proven by `test_mix_channel_uses_system_randomness`), but there is no live network transport yet. |
| Decoy **actions** (the glamour tool advertised to agents). | **Planned.** Only canary files are implemented today. |
| Cross-platform "a log an agent can't erase". | **Partial.** True on Windows via sentinel-vision's protection service; elsewhere the plugin log is an ordinary user file. |
| Signed sentinel votes / sentinels distributed across hosts. | **Planned.** The quorum is computed in a single process and votes are not themselves signed. |
