"""Tests for the NVD downloader's resume behaviour.

A resumed download appended a second full copy of the feed onto a complete local
file, producing 1.76 GB that was valid bytes and invalid JSON. The failure only
surfaced later, as a parse error a long way from its cause.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.data.downloader import NVDDownloader

BODY = b'[{"cve": {"id": "CVE-2026-0001"}}]'


class FakeResponse:
    def __init__(self, status_code, body, headers=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {"content-length": str(len(body))}

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=None):
        yield self._body


@pytest.fixture
def downloader(tmp_path):
    return NVDDownloader(
        output_file=tmp_path / "nvd.jsonl",
        source_url="https://example.invalid/nvd.jsonl",
        chunk_size=1024,
    )


def run_download(downloader, response, remote_size, resume=True):
    """Drive download() with a stubbed session, returning the request headers."""
    session = MagicMock()
    session.get.return_value = response

    with patch.object(downloader, "_get_session_with_retries", return_value=session):
        with patch.object(downloader, "_get_remote_size", return_value=remote_size):
            ok = downloader.download(resume=resume)

    _, kwargs = session.get.call_args
    return ok, kwargs.get("headers", {})


def test_complete_local_file_is_not_resumed_past_its_end(downloader):
    """The regression: a finished file is not a partial one.

    Resuming from the end of a complete file asks for bytes beyond the resource
    and appends whatever comes back to a file that was already whole.
    """
    downloader.output_file.write_bytes(BODY)  # already complete

    _, headers = run_download(downloader, FakeResponse(200, BODY), len(BODY))

    assert "Range" not in headers, "must not resume past the end of a complete file"
    assert downloader.output_file.read_bytes() == BODY  # one copy, not two


def test_a_range_reply_of_200_rewrites_rather_than_appends(downloader):
    """A 200 to a range request carries the whole body, not the tail."""
    downloader.output_file.write_bytes(b"partial")

    _, headers = run_download(downloader, FakeResponse(200, BODY), len(BODY) * 10)

    assert headers.get("Range") == "bytes=7-"  # it did ask to resume
    # ...but the server ignored it, so the file is replaced, not extended.
    assert downloader.output_file.read_bytes() == BODY


def test_a_genuine_206_appends(downloader):
    """The case resume exists for still works."""
    downloader.output_file.write_bytes(b"head")

    _, headers = run_download(downloader, FakeResponse(206, b"tail"), 8)

    assert headers.get("Range") == "bytes=4-"
    assert downloader.output_file.read_bytes() == b"headtail"


def test_no_resume_always_starts_from_scratch(downloader):
    downloader.output_file.write_bytes(b"stale content")

    _, headers = run_download(
        downloader, FakeResponse(200, BODY), len(BODY), resume=False
    )

    assert "Range" not in headers
    assert downloader.output_file.read_bytes() == BODY


def test_missing_file_downloads_whole(downloader):
    _, headers = run_download(downloader, FakeResponse(200, BODY), len(BODY))

    assert "Range" not in headers
    assert downloader.output_file.read_bytes() == BODY
