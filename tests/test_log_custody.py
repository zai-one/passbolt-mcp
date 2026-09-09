from zai_passbolt.adapter import PassboltAdapter
from zai_passbolt.transport import ProviderError


async def test_readiness_error_never_discloses_exception_text_with_default_logger(caplog):
    adapter = PassboltAdapter("https://vault.example", "fixture-access")
    adapter._configured = lambda: True

    async def fail(*args, **kwargs):
        raise ProviderError("synthetic-custody-marker-should-not-be-logged")

    adapter._request = fail
    result = await adapter.status()
    assert result["auth_ready"] is False
    assert "synthetic-custody-marker" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
