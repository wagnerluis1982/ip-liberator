#!/usr/bin/env python

"""Tests for `ip_liberator.utils` package."""

import typing
import unittest.mock

import pytest

from ip_liberator.utils import whats_my_ip, make_keys, duplicate_removal, make_rule, make_rules


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


def test_make_keys():
    rule = {
        'IpPermissions': [make_rule('Python', '10.0.0.1/32', port=1),
                          make_rule('IsCool', '10.0.0.2/32', from_port=2, to_port=9)]
    }
    expected = {
        (1, 1, 'Python', '10.0.0.1/32'): 0,
        (2, 9, 'IsCool', '10.0.0.2/32'): 1,
    }

    assert make_keys(rule) == expected


def test_duplicate_removal():
    rule1 = {
        'IpPermissions': [make_rule('Python', '10.0.0.1/32', port=1),
                          make_rule('IsCool', '10.0.0.2/32', port=2)]
    }
    rule2 = {
        'IpPermissions': [make_rule('Python', '10.0.0.1/32', port=1),
                          make_rule('Second', '10.0.0.2/32', port=2),
                          make_rule('ToNone', '10.0.0.3/32', port=3)]
    }

    duplicate_removal(rule1, rule2)
    assert len(rule1['IpPermissions']) == 1
    assert len(rule2['IpPermissions']) == 2
    assert rule1['IpPermissions'] == [make_rule('IsCool', '10.0.0.2/32', port=2)]
    assert rule2['IpPermissions'] == [make_rule('Second', '10.0.0.2/32', port=2),
                                      make_rule('ToNone', '10.0.0.3/32', port=3)]


def test_make_rule():
    rule_http = make_rule('HTTP', '10.0.0.1/32', port=80)
    rule_many = make_rule('Many Services', '10.0.0.1/32', from_port=1, to_port=1000)

    assert rule_http == {'FromPort': 80, 'ToPort': 80, 'IpProtocol': 'tcp',
                         'IpRanges': [{'CidrIp': '10.0.0.1/32', 'Description': 'HTTP'}]}
    assert rule_many == {'FromPort': 1, 'ToPort': 1000, 'IpProtocol': 'tcp',
                         'IpRanges': [{'CidrIp': '10.0.0.1/32', 'Description': 'Many Services'}]}


@unittest.mock.patch('ip_liberator.utils.whats_my_ip')
def test_make_rules(mock_ip):
    mock_ip.return_value = '10.0.0.1/32'

    rules = make_rules(config={"security_groups": ["sg-1"]},
                       services={"John SFTP": {"name": "SFTP", "port": "22"},
                                 "John HTTP": {"name": "HTTP", "port": "80"}})
    expected = {'GroupId': 'sg-1',
                'IpPermissions': [
                    {'FromPort': 22, 'ToPort': 22, 'IpProtocol': 'tcp',
                     'IpRanges': [{'CidrIp': '10.0.0.1/32', 'Description': 'John SFTP'}]},
                    {'FromPort': 80, 'ToPort': 80, 'IpProtocol': 'tcp',
                     'IpRanges': [{'CidrIp': '10.0.0.1/32', 'Description': 'John HTTP'}]}
                ]}

    assert isinstance(rules, typing.Iterator)
    assert next(rules) == expected
    with pytest.raises(StopIteration): next(rules)


@unittest.mock.patch('ip_liberator.utils.whats_my_ip')
def test_make_rules__no_port_range(mock_ip):
    mock_ip.return_value = '10.0.0.1/32'

    ports_input = [
        "",
        " ",
        "\t\n "
    ]

    for port in ports_input:
        rules = make_rules(config={"security_groups": ["sg-1"]},
                           services={"SVC": {"port": port}})

        with pytest.raises(ValueError, match="No port range informed in service: SVC"):
            next(rules)



@unittest.mock.patch('ip_liberator.utils.whats_my_ip')
def test_make_rules__invalid_port_range(mock_ip):
    mock_ip.return_value = '10.0.0.1/32'

    ports_input = [
        "1-2-3",
        "100-",
        "-100",
        "abc",
        "1 2 3",
    ]

    for port in ports_input:
        rules = make_rules(config={"security_groups": ["sg-1"]},
                           services={"SVC": {"port": port}})

        with pytest.raises(ValueError, match="Invalid port range: '%s'" % port):
            next(rules)
