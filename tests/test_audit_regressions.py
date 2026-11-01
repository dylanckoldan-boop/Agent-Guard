# Regression tests from the October 2026 audit (findings AG-A01 ... AG-F09, plus website checks).
# Every test above the guards at the end fails on v0.1.0 (commit 0a88db5) and must pass once its finding is fixed.
# Run `ruff format` after adding the file (it is written with single quotes so it can be pasted from a doc).

import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

import psutil
import pytest

import foldward.cli as cli
import foldward.crypto as crypto
import foldward.mesh as mesh
from foldward import detect
from foldward.config import Settings
from foldward.core import Foldward
from foldward.detect import DetectedAgent, Detector, ProcessInfo
from foldward.identity import Scope, TrustDomain
from foldward.integrations import sentinel_vision as sv_integ
from foldward.quarantine import Quarantine
from foldward.registry import Revocation, RevocationRegistry
from foldward.response import RUNG_BY_NAME, Containment, Rung

ROOT = Path(__file__).resolve().parents[1]
CREWAI = ['python', '-m', 'crewai', 'run']
UNUSED_PID = 4_194_304 + 1000  # above the largest Linux PID, so no real process is ever touched


def rogue(pid, cmdline, open_files=()):
    # unregistered, 11 public peers, 6 children: scores well above the flag threshold
    hosts = [f'8.8.{i}.8:443' for i in range(10)] + ['api.openai.com:443']
    return ProcessInfo(
        pid=pid,
        name='python',
        exe='',
        cmdline=list(cmdline),
        remote_hosts=hosts,
        child_count=6,
        touched_paths=list(open_files),
    )


def live(proc_handle, create_time=None):
    # a ProcessInfo for a real child process, as the detector would have recorded it
    p = psutil.Process(proc_handle.pid)
    return ProcessInfo(
        pid=p.pid,
        name='python',
        exe='',
        cmdline=CREWAI,
        create_time=p.create_time() if create_time is None else create_time,
    )


def wait_for_status(pid, wanted, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if psutil.Process(pid).status() == wanted:
            return True
        time.sleep(0.05)
    return psutil.Process(pid).status() == wanted


# AG-A01 / AG-F01
def test_foldward_marker_does_not_hide_an_agent():
    secret = str(Path.home() / 'Documents' / 'secret.pdf')
    proc = rogue(UNUSED_PID, [*CREWAI, '--tag', 'foldward'], [secret])
    d = Detector(Settings())
    d.snapshot_processes = lambda: [proc]
    found = d.detect()
    assert [x.pid for x in found] == [proc.pid], 'a command line must never exclude a process'
    assert found[0].score >= Settings().risk_flag_threshold


# AG-A02
def test_canary_contact_trips_during_a_normal_scan(tmp_path):
    s = Settings()
    s.auto_contain_on_decoy = False  # observe only; this test must not act on anything
    bait = tmp_path / 'bait'
    bait.mkdir()
    planted = Foldward(s).plant_canaries([str(bait)])  # e.g. the 'canaries' command
    g = Foldward(s)  # e.g. a later 'watch' run
    proc = rogue(UNUSED_PID + 1, CREWAI, [planted[0]])
    g.detector.snapshot_processes = lambda: [proc]
    [res] = g.scan()
    assert res.score == 100
    assert any(r.kind == 'tripwire' for r in res.reasons)
    assert g.tripwire.trips == 1


# AG-A03
def test_state_survives_a_restart():
    a = Foldward(Settings())
    ident = a.register_agent('researcher', Scope(allowed_hosts=frozenset({'api.anthropic.com'})), pid=4321, create_time=1700000000.0)
    a.registry.revoke('agent-x', 'test', a.signer)
    b = Foldward(Settings())
    assert [i.agent_id for i in b.sanctioned()] == [ident.agent_id]
    assert b.registry.is_revoked('agent-x')
    assert b.signer.public_ref == a.signer.public_ref
    assert [e.data['agent'] for e in b.audit.events('admission.registered')] == [ident.agent_id]
    assert b.audit.verify()[0]


# AG-A04 / AG-C04
@pytest.mark.skipif(sys.platform == 'win32', reason='uses a POSIX shell script as the impostor')
def test_sentinel_vision_cli_is_not_taken_from_path(tmp_path, monkeypatch):
    monkeypatch.setattr(sv_integ, 'shutil', shutil)  # undo the conftest stub: use the real PATH lookup
    fake = tmp_path / 'bin' / 'sentinel-vision-cli'
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh' + chr(10) + 'exit 0' + chr(10), encoding='utf-8')
    fake.chmod(0o755)
    monkeypatch.setenv('PATH', str(fake.parent) + os.pathsep + os.environ.get('PATH', ''))
    assert sv_integ.probe()[0] is False, 'a program on PATH must not be trusted as Sentinel Vision'
    assert type(sv_integ.make_containment(None)) is Containment


# AG-A05
def test_interpreter_is_never_quarantined(tmp_path, sleeper, monkeypatch):
    script = tmp_path / 'agent.py'
    script.write_text('print(1)' + chr(10), encoding='utf-8')
    exe = os.path.realpath(sys.executable)
    proc = live(sleeper)
    proc.exe, proc.cmdline = exe, [exe, str(script)]
    g = Foldward(Settings())
    asked = []  # record what the quarantine step is asked to take; never let it touch the real interpreter
    monkeypatch.setattr(g.containment, 'quarantine_binary', lambda path, agent_id, reason: asked.append(path) or 'ok')
    g.pacify(DetectedAgent(proc.pid, 'python', proc, False, 90, [], 'flagged'), rung='quarantine')
    assert exe not in asked, 'the interpreter itself was sent to quarantine'
    assert str(script) in asked, 'the script the interpreter runs should be quarantined instead'


# AG-A06
def test_pacify_refuses_a_reused_pid(sleeper):
    proc = live(sleeper, create_time=psutil.Process(sleeper.pid).create_time() - 1000)  # a different, older process
    g = Foldward(Settings())
    try:
        g.pacify(DetectedAgent(proc.pid, 'python', proc, False, 90, [], 'flagged'), rung='suspend')
        assert not wait_for_status(sleeper.pid, psutil.STATUS_STOPPED, timeout=1.0), 'acted on the wrong process'
    finally:
        psutil.Process(sleeper.pid).resume()


# AG-A07
def test_own_quarantine_moves_the_file(tmp_path):
    original = tmp_path / 'agent.bin'
    data = b'MZ-pretend-agent' * 64
    original.write_bytes(data)
    q = Quarantine()
    item = q.add(str(original), 'pid:1', 'test')
    assert not original.exists(), 'the original must not stay runnable where it was'
    assert Path(q.restore(item.item_id, str(tmp_path / 'restored.bin'))).read_bytes() == data


# AG-A08
def test_resumed_agent_is_suspended_again(sleeper):
    proc = live(sleeper)
    g = Foldward(Settings())
    g.detector.snapshot_processes = lambda: []  # never look at the real process table in tests
    alerts = []
    g.alert_listeners.append(lambda title, text, level: alerts.append(title + ' ' + text))
    g.pacify(DetectedAgent(proc.pid, 'python', proc, False, 90, [], 'flagged'), rung='suspend')
    assert wait_for_status(sleeper.pid, psutil.STATUS_STOPPED)
    psutil.Process(sleeper.pid).resume()  # the agent, or a helper it started, undoes the suspension
    g.scan()
    assert wait_for_status(sleeper.pid, psutil.STATUS_STOPPED), 'the next scan must suspend it again'
    assert any('tamper' in a.lower() for a in alerts)


# AG-A09
def test_auto_signer_never_falls_back_to_hmac(monkeypatch):
    monkeypatch.setattr(crypto, '_HAVE_MLDSA', False)
    monkeypatch.setattr(crypto, '_HAVE_ED25519', False)
    with pytest.raises(crypto.SignatureError):
        crypto.new_signer('auto')


# AG-A10 / AG-B02
def test_workflow_actions_are_pinned_to_a_commit():
    unpinned = []
    for wf in sorted((ROOT / '.github' / 'workflows').glob('*.yml')):
        for line in wf.read_text(encoding='utf-8').splitlines():
            m = re.search('uses:[ ]*([^ #]+)', line)
            if m and not m.group(1).startswith('./'):
                ref = m.group(1).rpartition('@')[2]
                if not re.fullmatch('[0-9a-f]{40}', ref):
                    unpinned.append(wf.name + ': ' + m.group(1))
    assert unpinned == []


# AG-F02
@pytest.mark.parametrize('cmd', [['/usr/bin/ssh-agent', '-s'], ['gpg-agent', '--daemon'], ['code', '--user-agent=x']])
def test_system_agents_are_not_ai_agents(cmd):
    proc = ProcessInfo(1234, cmd[0].rpartition('/')[2], cmd[0], cmd)
    assert not detect.looks_like_agent(proc, Settings())


# AG-F03
@pytest.mark.parametrize('ip', ['172.217.14.206', '172.64.0.1', '172.32.0.1'])
def test_public_172_addresses_are_not_local(ip):
    assert not detect._is_local(ip)  # if the helper moves, update this import, not the expectation


@pytest.mark.parametrize('ip', ['fe80::1', 'fd00::1', '::ffff:192.168.1.2'])
def test_link_local_and_unique_local_addresses_are_local(ip):
    assert detect._is_local(ip)


# AG-F04
def test_scope_path_needs_a_separator(tmp_path):
    root = tmp_path / 'project'
    s = Scope(allowed_path_prefixes=frozenset({str(root)}))
    assert s.permits_path(str(root / 'notes.txt'))
    assert not s.permits_path(str(tmp_path / 'project-secrets' / 'keys.txt'))
    assert not s.permits_path(str(root) + '/../.ssh/id_rsa')


# AG-F05
def test_settings_with_wrong_types_fall_back_to_defaults():
    defaults = Settings()
    raw = {
        'agent_markers': 'agent',
        'risk_flag_threshold': '60',
        'scan_interval_s': -1,
        'mix_min_cover': 10**9,
        'report_only': 0,
    }
    Settings.path().write_text(json.dumps(raw), encoding='utf-8')
    s = Settings.load()
    assert s.agent_markers == defaults.agent_markers
    assert s.risk_flag_threshold == defaults.risk_flag_threshold
    assert s.scan_interval_s == defaults.scan_interval_s
    assert s.mix_min_cover == defaults.mix_min_cover
    assert s.report_only is True


def test_settings_cannot_empty_the_detection_lists():
    Settings.path().write_text(json.dumps({'agent_markers': [], 'llm_hosts': []}), encoding='utf-8')
    proc = ProcessInfo(1234, 'python', '/usr/bin/python3', CREWAI)
    assert detect.looks_like_agent(proc, Settings.load())


# AG-F06
def test_restore_requires_a_destination(tmp_path, capsys):
    original = tmp_path / 'agent.bin'
    original.write_bytes(b'MZ' * 8)
    item = Quarantine().add(str(original), 'pid:1', 'test')
    try:
        code = cli.main(['quarantine', 'restore', item.item_id])
    except SystemExit as exc:  # argparse refusing a missing --to is a fine outcome
        code = exc.code
    err = capsys.readouterr().err
    assert code != 0
    assert 'NoneType' not in err, 'a missing --to must give a clear message, not a Python error'
    assert '--to' in err


# AG-F07
def _accepted(registry, rev):
    try:
        return registry.submit(rev)
    except ValueError:  # refusing a malformed revocation outright is also correct
        return False


def test_signed_messages_are_unambiguous(signer):
    cred = TrustDomain(signer).issue('agent-1', Scope(allowed_hosts=frozenset({'api.anthropic.com'})))
    reg = RevocationRegistry(signer.verifier())
    replay = Revocation(
        agent_id='agent-1',
        reason=cred.scope.canonical(),
        issuer_ref=cred.issuer_ref,
        issued_at=cred.issued_at,
        signature=cred.signature,
    )
    assert not _accepted(reg, replay), 'a credential signature must not work as a revocation'
    assert reg.revoke('agent-2', 'b|c', signer)
    good = reg.get('agent-2')
    shifted = Revocation(
        agent_id='agent-2|b',
        reason='c',
        issuer_ref=good.issuer_ref,
        issued_at=good.issued_at,
        signature=good.signature,
    )
    assert not _accepted(reg, shifted), 'moving a separator must break the signature'


# AG-F09
def _wire(item):
    return bytes(item) if isinstance(item, (bytes, bytearray)) else json.dumps(item, sort_keys=True).encode()


def test_mix_channel_uses_system_randomness(monkeypatch):
    def mersenne(*args, **kwargs):
        raise AssertionError('random.Random is predictable; use secrets.SystemRandom')

    monkeypatch.setattr(mesh.random, 'Random', mersenne)
    channel = mesh.MixChannel(enabled=True, min_cover=3)
    wire = [_wire(x) for x in channel.emit({'kind': 'vote', 'agent': 'pid:1', 'risk': 50})]
    assert len(wire) == 4
    assert len({len(w) for w in wire}) == 1, 'real and cover records must be the same size'
    assert not any(b'_cover' in w for w in wire), 'what is emitted must not say which record is cover'


# AG-C03
def _requirement_name(token):
    name = token.strip('"' + chr(39)).lower()
    for i, ch in enumerate(name):
        if ch in '=<>~!;[':
            return name[:i]
    return name


def test_install_commands_never_fetch_the_unrelated_pypi_package():
    offenders = []
    files = [ROOT / 'README.md', *sorted((ROOT / 'docs').glob('*.md')), *sorted((ROOT / 'site').glob('*.html'))]
    for f in files:
        for line in f.read_text(encoding='utf-8').splitlines():
            if 'pip install' not in line:
                continue
            rest = line.split('pip install', 1)[1]
            if '@ git+https://github.com/dylanckoldan-boop/Foldward@v' in rest:
                continue  # a direct reference to a tagged release of this repository, never a PyPI name
            names = {_requirement_name(t) for t in rest.split()}
            if names & {'foldward', 'agent-guard', 'agent_guard'}:
                offenders.append(f.name + ': ' + line.strip())
    assert offenders == [], (
        "PyPI 'agent-guard' is an unrelated project and 'foldward' isn't claimed there; "
        'install a tagged release from the repository'
    )


# AG-B01
def test_site_pages_have_a_content_security_policy_and_no_inline_styles():
    for page in sorted((ROOT / 'site').glob('*.html')):
        html = page.read_text(encoding='utf-8')
        assert 'http-equiv="Content-Security-Policy"' in html, page.name
        assert 'name="referrer"' in html, page.name
        assert ' style="' not in html, page.name


# AG-E03
def _luminance(colour):
    channels = [int(colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(a, b):
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_light_mode_link_contrast_is_at_least_4_5():
    css = (ROOT / 'site' / 'style.css').read_text(encoding='utf-8')
    light = css.split('@media (prefers-color-scheme: light)')[1].split('}')[0]

    def var(name):
        return re.search(name + ':[ ]*(#[0-9a-fA-F]{6})', light).group(1)

    for background in ('--bg', '--surface'):
        ratio = _contrast(var('--accent'), var(background))
        assert ratio >= 4.5, f'--accent on {background}: {ratio:.2f}:1'


# Guards: these pass today and keep the fixes above from over-correcting
def test_automatic_containment_never_grows():
    s = Settings()
    assert s.report_only is True
    assert RUNG_BY_NAME[s.auto_contain_max_rung] <= Rung.SUSPEND


def test_real_agent_runtimes_are_still_candidates():
    for cmd in (CREWAI, ['python', '-m', 'autogen', 'serve'], ['python', 'app.py', '--framework', 'langgraph']):
        assert detect.looks_like_agent(ProcessInfo(1234, 'python', '/usr/bin/python3', cmd), Settings()), cmd


@pytest.mark.parametrize(
    'ip,local',
    [('10.0.0.5', True), ('172.16.0.1', True), ('127.0.0.1', True), ('::1', True), ('2606:4700:4700::1111', False)],
)
def test_address_cases_that_are_already_right(ip, local):
    assert detect._is_local(ip) is local
