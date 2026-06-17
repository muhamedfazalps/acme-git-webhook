from unittest.mock import patch, MagicMock

import dns.exception
import dns.rdatatype
import dns.resolver
import dns.rdtypes.txtbase
import pytest

from app.dns_probe import _check_single_ns, check_propagation


def _make_txt_rdata(value: str):
    """Create a minimal TXT-like rdata for testing."""
    return dns.rdtypes.txtbase.TXTBase(
        dns.rdataclass.IN, dns.rdatatype.TXT, [value.encode()],
    )


class TestCheckSingleNs:
    def test_match(self):
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("abc123")]
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            assert _check_single_ns("_acme-challenge.example.com.", "abc123", "8.8.8.8")

    def test_no_match(self):
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("wrong")]
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            assert not _check_single_ns("_acme-challenge.example.com.", "expected", "8.8.8.8")

    def test_dns_error(self):
        with patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.DNSException):
            assert not _check_single_ns("_acme-challenge.example.com.", "val", "8.8.8.8")

    def test_empty_answer(self):
        answer = MagicMock()
        answer.__iter__.return_value = []
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            assert not _check_single_ns("_acme-challenge.example.com.", "val", "8.8.8.8")


class TestCheckPropagation:
    def test_all_propagated(self):
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("token")]
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            result = check_propagation(
                "_acme-challenge.example.com", "token",
                ["1.1.1.1", "8.8.8.8"], timeout=10, poll_interval=1,
            )
        assert result["pending"] == []
        assert len(result["matched"]) == 2
        assert result["elapsed"] == 0

    def test_partial_then_full(self):
        call_count = [0]

        def _resolve_side(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 2:
                raise dns.exception.DNSException()
            answer = MagicMock()
            answer.__iter__.return_value = [_make_txt_rdata("token")]
            return answer

        with patch.object(dns.resolver.Resolver, "resolve", side_effect=_resolve_side):
            result = check_propagation(
                "_acme-challenge.example.com", "token",
                ["8.8.8.8"], timeout=10, poll_interval=0,
            )
        assert result["pending"] == []
        assert result["matched"] == ["8.8.8.8"]

    def test_all_pending_timeout(self):
        with patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.DNSException):
            result = check_propagation(
                "_acme-challenge.example.com", "token",
                ["1.1.1.1", "8.8.8.8"], timeout=1, poll_interval=1,
            )
        assert result["pending"] == ["1.1.1.1", "8.8.8.8"]
        assert result["matched"] == []
        assert result["elapsed"] == 1

    def test_custom_nameservers(self):
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("x")]
        custom_ns = ["4.4.4.4", "8.8.4.4"]
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer) as mock:
            result = check_propagation(
                "_acme-challenge.example.com", "x",
                custom_ns, timeout=10, poll_interval=1,
            )
        assert result["matched"] == custom_ns

    def test_wrong_value_treated_as_pending(self):
        """If the TXT exists but has a different value, it should still be pending."""
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("old-token")]
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            result = check_propagation(
                "_acme-challenge.example.com", "expected-token",
                ["8.8.8.8"], timeout=1, poll_interval=1,
            )
        assert result["pending"] == ["8.8.8.8"]


class TestCheckPropagationEdgeCases:
    def test_poll_interval_respected(self):
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("token")]
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            result = check_propagation(
                "_acme-challenge.example.com", "token",
                ["8.8.8.8"], timeout=30, poll_interval=5,
            )
        # With immediate match, elapsed should be 0 (first poll succeeds).
        assert result["elapsed"] == 0
