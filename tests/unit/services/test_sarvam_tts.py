import base64

from backend.services.sarvam_tts import synthesize, SarvamTTSError


class FakeResult:
    def __init__(self, payload: bytes):
        self.audios = [base64.b64encode(payload).decode()]


class FakeClient:
    def __init__(self):
        self.calls = []

    def convert(self, **kwargs):
        self.calls.append(kwargs)
        return FakeResult(b"RIFF-test")


def test_synthesize_uses_sanitized_chunks_and_order():
    client = FakeClient()
    clips = synthesize("## Summary\nSee [EV-003].", client=client, language="en-IN", speaker="shubh")
    assert [c.sequence for c in clips] == [0]
    assert clips[0].audio_bytes == b"RIFF-test"
    assert client.calls[0]["model"] == "bulbul:v3"
    assert "evidence 3" in client.calls[0]["text"]


def test_provider_failure_is_normalized():
    class BrokenClient:
        def convert(self, **kwargs):
            raise RuntimeError("boom")

    try:
        synthesize("Hello.", client=BrokenClient())
    except SarvamTTSError as exc:
        assert "Sarvam TTS request failed" in str(exc)
    else:
        raise AssertionError("SarvamTTSError was not raised")
