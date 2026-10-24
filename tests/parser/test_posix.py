from commandcompass.parsers.posix import PosixParser


def parse(cmd):
    return PosixParser().parse(cmd)


def test_simple_command():
    r = parse("ls -la")
    assert r.shell == "posix"
    assert len(r.commands) == 1
    assert r.commands[0].name == "ls"
    assert r.commands[0].args == ["-la"]
    assert r.complete is True


def test_pipe():
    r = parse("echo hi | grep hi")
    assert len(r.pipelines) == 1
    assert len(r.pipelines[0].commands) == 2
    assert r.pipelines[0].commands[1].name == "grep"


def test_chain():
    r = parse("mkdir foo && cd foo")
    assert "&&" in r.chains


def test_redirection():
    r = parse("echo hi > out.txt")
    assert any(">" in red for red in r.redirections)
    assert r.commands[0].redirections


def test_quoting():
    r = parse('echo "hello world"')
    assert r.commands[0].args == ["hello world"]


def test_env_var():
    r = parse("echo $HOME")
    assert "$HOME" in r.env_vars


def test_substitution():
    r = parse("echo $(pwd)")
    assert r.substitutions
    assert r.complete is False or r.confidence < 1.0


def test_wildcard_note():
    r = parse("rm *.tmp")
    assert any("Wildcard" in n for n in r.notes)


def test_unterminated_quote():
    r = parse("echo 'unterminated")
    # should not crash
    assert r.commands


def test_empty():
    r = parse("")
    assert r.commands == []
