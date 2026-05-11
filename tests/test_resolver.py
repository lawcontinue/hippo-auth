"""Tests for resolver.py — resolve_keyid and build_well_known."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from hippo_auth.resolver import resolve_keyid, build_well_known


class TestBuildWellKnown:
    def test_basic(self):
        result = build_well_known("pubkey123", "0xabc")
        assert result == {"address": "0xabc", "public_key": "pubkey123"}

    def test_empty_values(self):
        result = build_well_known("", "")
        assert result == {"address": "", "public_key": ""}


def _mock_httpx_get(return_value=None, side_effect=None):
    """Create a mock for httpx.get."""
    mock_resp = MagicMock()
    if return_value is not None:
        mock_resp.json.return_value = return_value
    mock_resp.raise_for_status = MagicMock()
    mock = MagicMock()
    if side_effect is not None:
        mock.get.side_effect = side_effect
    else:
        mock.get.return_value = mock_resp
    return mock


class TestResolveKeyid:
    @patch("httpx.get")
    def test_resolve_https(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"address": "0x1", "public_key": "pk1"}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = resolve_keyid("https://example.com/key")
        assert result == {"address": "0x1", "public_key": "pk1"}
        mock_get.assert_called_once_with("https://example.com/key", timeout=10.0)

    @patch("httpx.get")
    def test_resolve_custom_timeout(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"address": "0x1", "public_key": "pk1"}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        resolve_keyid("https://example.com/key", timeout=5.0)
        mock_get.assert_called_once_with("https://example.com/key", timeout=5.0)

    def test_reject_http_by_default(self):
        with pytest.raises(ValueError, match="Plain HTTP"):
            resolve_keyid("http://example.com/key")

    def test_reject_invalid_scheme(self):
        with pytest.raises(ValueError, match="Invalid keyid URL scheme"):
            resolve_keyid("ftp://example.com/key")

    @patch("httpx.get")
    def test_allow_http_explicit(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"address": "0x1", "public_key": "pk1"}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = resolve_keyid("http://localhost:8080/key", allow_http=True)
        assert result["public_key"] == "pk1"

    @patch("httpx.get")
    def test_missing_public_key(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"address": "0x1"}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        with pytest.raises(ValueError, match="No public_key"):
            resolve_keyid("https://example.com/key")

    @patch("httpx.get")
    def test_http_error(self, mock_get):
        mock_get.side_effect = Exception("connection error")
        with pytest.raises(Exception, match="connection error"):
            resolve_keyid("https://example.com/key")


class TestHttpxOptional:
    def test_missing_httpx_raises_import_error(self):
        with patch.dict("sys.modules", {"httpx": None}):
            with pytest.raises(ImportError, match="hippo-auth\\[resolver\\]"):
                resolve_keyid("https://example.com/key")
