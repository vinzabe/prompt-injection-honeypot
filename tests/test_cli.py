import json

import pytest

from pihoney.cli import EXIT_AGENT, EXIT_ERROR, EXIT_OK, main


def _args(tmp_path, *rest):
    return ["--db", str(tmp_path / "c.db"), "--secret", "s", *rest]


def test_plant_outputs_bait(tmp_path, capsys):
    assert main(_args(tmp_path, "plant", "docs/a.html")) == EXIT_OK
    assert "<!--" in capsys.readouterr().out


def test_secret_required(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("PIHONEY_SECRET", raising=False)
    rc = main(["--db", str(tmp_path / "c.db"), "plant", "a"])
    assert rc == EXIT_ERROR
    assert "secret is required" in capsys.readouterr().err


def test_agent_trigger_exits_2(tmp_path, capsys):
    main(_args(tmp_path, "plant", "docs/a.html", "--json"))
    token = json.loads(capsys.readouterr().out)["token"]
    rc = main(_args(tmp_path, "trigger", token, "--user-agent", "claude-agent"))
    assert rc == EXIT_AGENT


def test_crawler_trigger_exits_0(tmp_path, capsys):
    main(_args(tmp_path, "plant", "docs/a.html", "--json"))
    token = json.loads(capsys.readouterr().out)["token"]
    rc = main(_args(tmp_path, "trigger", token, "--user-agent", "Googlebot",
                    "--no-host-page"))
    assert rc == EXIT_OK


def test_unknown_token_rejected(tmp_path, capsys):
    rc = main(_args(tmp_path, "trigger", "notaplantedtoken"))
    assert rc == EXIT_ERROR
    assert "rejected" in capsys.readouterr().err


def test_report_json(tmp_path, capsys):
    main(_args(tmp_path, "plant", "docs/a.html"))
    capsys.readouterr()
    main(_args(tmp_path, "report", "--json"))
    d = json.loads(capsys.readouterr().out)
    assert d["actionable_agent_triggers"] == 0
    assert len(d["surfaces"]) == 1


def test_version():
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
