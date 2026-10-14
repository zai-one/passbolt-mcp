from types import SimpleNamespace

import pytest

from zai_passbolt import elicitation as el


def _ctx(action, supported=True):
    caps = SimpleNamespace(elicitation=object() if supported else None)
    session = SimpleNamespace(client_params=SimpleNamespace(capabilities=caps))

    async def elicit(message, response_type=None):
        _ctx.last = message
        return SimpleNamespace(action=action)

    return SimpleNamespace(session=session, elicit=elicit)


def test_summary_lists_recipients():
    text = el.share_summary("resource", "r1", ["g1"], ["u1", "u2"], "update")
    assert "1 group(s): g1" in text and "2 user(s)" in text and "'update'" in text


@pytest.mark.parametrize(("action", "ok"), [("accept", True), ("decline", False), ("cancel", False)])
async def test_confirm_share_actions(monkeypatch, action, ok):
    monkeypatch.setattr(el, "get_context", lambda: _ctx(action))
    if ok:
        assert await el.confirm_share("m") == "accepted"
    else:
        with pytest.raises(PermissionError):
            await el.confirm_share("m")


async def test_unsupported_client_auto_vs_required(monkeypatch):
    monkeypatch.setattr(el, "get_context", lambda: _ctx("accept", supported=False))
    assert await el.confirm_share("m", "auto") == "skipped"
    with pytest.raises(PermissionError):
        await el.confirm_share("m", "required")


async def test_off_and_bad_mode(monkeypatch):
    assert await el.confirm_share("m", "off") == "skipped"
    with pytest.raises(ValueError):
        await el.confirm_share("m", "maybe")


async def test_elicitation_error_fails_closed(monkeypatch):
    ctx = _ctx("accept")

    async def boom(message, response_type=None):
        raise RuntimeError("transport")

    ctx.elicit = boom
    monkeypatch.setattr(el, "get_context", lambda: ctx)
    with pytest.raises(PermissionError):
        await el.confirm_share("m")


@pytest.mark.parametrize("mode", ["maybe", "", "REQUIRED"])
def test_invalid_mode_rejected_at_startup(config, mode):
    from dataclasses import replace

    with pytest.raises(ValueError):
        replace(config, passbolt_share_elicitation=mode)
    assert replace(config, passbolt_share_elicitation="required").passbolt_share_elicitation == "required"
