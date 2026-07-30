"""Tests for dns_monitor.model.snapshot."""
from __future__ import annotations

from dns_monitor.model import snapshot as snap_io
from tests.conftest import make_record


def test_save_load_roundtrip(tmp_path):
    path = tmp_path / "latest.json"
    zones = {
        "inwx:example.com": [
            make_record(name="example.com", type="MX", content="mail.example.com", ttl=3600),
            make_record(name="www.example.com", type="A", content="8.8.8.8", ttl=3600),
        ],
    }
    snap_io.save(zones, path)
    loaded = snap_io.load(path)

    assert loaded is not None
    assert "inwx:example.com" in loaded
    recs = loaded["inwx:example.com"]
    assert len(recs) == 2
    assert recs[0].name == "example.com"
    assert recs[0].type == "MX"
    assert recs[1].content == "8.8.8.8"


def test_load_nonexistent(tmp_path):
    assert snap_io.load(tmp_path / "missing.json") is None


def test_save_creates_parent_dirs(tmp_path):
    path = tmp_path / "deep" / "nested" / "latest.json"
    snap_io.save({"inwx:example.com": [make_record()]}, path)
    assert path.exists()


def test_roundtrip_preserves_provider(tmp_path):
    path = tmp_path / "snap.json"
    zones = {
        "inwx:example.com": [make_record(provider="inwx")],
        "cloudflare:jerm.uk": [make_record(provider="cloudflare", zone="jerm.uk")],
    }
    snap_io.save(zones, path)
    loaded = snap_io.load(path)
    assert loaded["inwx:example.com"][0].provider == "inwx"
    assert loaded["cloudflare:jerm.uk"][0].provider == "cloudflare"


def test_roundtrip_proxied_flag(tmp_path):
    path = tmp_path / "snap.json"
    zones = {"cloudflare:jerm.uk": [make_record(proxied=True)]}
    snap_io.save(zones, path)
    loaded = snap_io.load(path)
    assert loaded["cloudflare:jerm.uk"][0].proxied is True
