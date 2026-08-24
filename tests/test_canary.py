import pytest

from pihoney.canary import CanaryError, Placement, mint, mint_token, render_bait


def _p(pid="docs/a.html", surface="web"):
    return Placement(pid, surface)


def test_tokens_are_unique_per_placement():
    a = mint_token("s", _p("docs/a.html"))
    b = mint_token("s", _p("docs/b.html"))
    assert a != b


def test_tokens_are_deterministic():
    assert mint_token("s", _p()) == mint_token("s", _p())


def test_surface_is_part_of_identity():
    assert mint_token("s", _p(surface="web")) != mint_token("s", _p(surface="email"))


def test_different_secret_different_token():
    assert mint_token("s1", _p()) != mint_token("s2", _p())


def test_empty_secret_rejected():
    with pytest.raises(CanaryError, match="secret"):
        mint_token("", _p())


def test_verify_accepts_own_token():
    c = mint("s", _p())
    assert c.verify("s")


def test_verify_rejects_wrong_secret():
    assert not mint("s", _p()).verify("other")


def test_bait_contains_token_and_is_hidden_by_default():
    c = mint("s", _p())
    bait = render_bait(c, "https://x.test")
    assert c.token in bait
    assert bait.startswith("<!--")


def test_visible_bait_has_no_comment_wrapper():
    bait = render_bait(mint("s", _p()), "https://x.test", hidden=False)
    assert not bait.startswith("<!--")


def test_bait_requests_no_data_or_credentials():
    """The bait must only cause a fetch — never ask for data or actions."""
    bait = render_bait(mint("s", _p()), "https://x.test").lower()
    for danger in ("password", "credential", "api key", "secret", "delete",
                   "send", "email the", "exfiltrate"):
        assert danger not in bait
