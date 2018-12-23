#!/usr/bin/env python

"""Tests for `ip_liberator.utils` package."""

import unittest.mock

from ip_liberator.utils import whats_my_ip


class TestWhatsMyIp:
    def setup_method(self):
        if hasattr(whats_my_ip, 'cache'):
            del whats_my_ip.cache

    @unittest.mock.patch('urllib.request.urlopen')
    def test_whats_my_ip(self, mock_urlopen):
        mock_response = unittest.mock.NonCallableMagicMock(status=200, **{'read.return_value': b'127.0.0.1'})
        mock_response.__enter__ = lambda self: self
        mock_urlopen.return_value = mock_response

        assert whats_my_ip() == '127.0.0.1/32'
        assert hasattr(whats_my_ip, 'cache')
        assert whats_my_ip.cache == '127.0.0.1/32'

        mock_urlopen.assert_called_once_with("https://checkip.amazonaws.com/")

    @unittest.mock.patch('urllib.request.urlopen')
    def test_whats_my_ip__fail(self, mock_urlopen):
        assert whats_my_ip() is None
        assert not hasattr(whats_my_ip, 'cache')

        mock_urlopen.assert_called_once_with("https://checkip.amazonaws.com/")

    def test_whats_my_ip__cache(self):
        value = 'Python is Cool'

        with unittest.mock.patch('urllib.request.urlopen'):
            assert whats_my_ip(value) == value
            assert hasattr(whats_my_ip, 'cache')
            assert whats_my_ip.cache == value
