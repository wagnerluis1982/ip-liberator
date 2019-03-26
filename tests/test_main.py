#!/usr/bin/env python

"""Tests for `ip_liberator.__main__` package."""
import json
import os
import tempfile
from unittest import mock

from ip_liberator.__main__ import main, make_services_index
from ip_liberator.utils import make_rules, make_rule

IP = '127.0.0.1/8'


@mock.patch('ip_liberator.__main__.AwsIpLiberator')
@mock.patch('ip_liberator.__main__.print')
@mock.patch('ip_liberator.utils.whats_my_ip', lambda: IP)
class TestMain:
    def setup_method(self):
        (self.fd, self.filename) = tempfile.mkstemp()

    def teardown_method(self):
        os.remove(self.filename)

    def test_main(self, mock_print, mock_aws_class):
        # given
        access_key = "LT7F9TDQ"
        secret_key = "SAERB0DITUERDQTYYX8Q"
        region_name = "sa-west-1"
        operator = "Fighter"
        services = [{"name": "HTTP", "port": "80"}]
        security_groups = ["sg-1"]

        # given
        settings = make_settings(access_key, secret_key, region_name, operator, services, security_groups)
        index = make_services_index(settings)
        rule = next(make_rules(index, settings['config']))

        # given
        with os.fdopen(self.fd, mode='w') as file:
            json.dump(settings, file)

        # when
        main(args=["--profile", self.filename])

        # then
        mock_print.assert_has_calls([mock.call("Authorizing rules", [svc for svc in index], "to IP", IP),
                                     mock.call('-', security_groups[0])])

        # then
        mock_aws_class.assert_called_once_with(access_key, secret_key, region_name)
        mock_liberator = mock_aws_class.return_value
        mock_liberator.describe_rules.assert_called_once_with(index, settings['config'])
        mock_liberator.authorize_rule.assert_called_once_with(rule)

    def test_main__revoke_only(self, mock_print, mock_aws_class):
        # given
        group_id = "sg-1"
        rule_to_revoke = {'GroupId': group_id}
        settings = make_settings(security_groups=[group_id])
        index = make_services_index(settings)

        # given
        with os.fdopen(self.fd, mode='w') as file:
            json.dump(settings, file)

        # given
        mock_liberator = mock_aws_class.return_value
        mock_liberator.describe_rules.return_value = [rule_to_revoke]

        # when
        main(args=["--profile", self.filename, "--revoke-only"])

        # then
        mock_print.assert_has_calls([mock.call("Revoking rules", [svc for svc in index]),
                                     mock.call('-', group_id)])

        # then
        mock_liberator.describe_rules.assert_called_once_with(index, settings['config'])
        mock_liberator.revoke_rule.assert_called_once_with(rule_to_revoke)

    def test_main__duplicate_rule(self, mock_print, mock_aws_class):
        # given
        group_id = "sg-1"
        rule_to_revoke = {'GroupId': group_id,
                          'IpPermissions': [make_rule('Monty Python', IP, port=1),
                                            make_rule('Monty Second', IP, port=2),
                                            make_rule('Monty ToNone', IP, port=3)]}
        settings = make_settings(security_groups=[group_id],
                                 operator='Monty',
                                 services=[{"name": "Python", "port": "1"},
                                           {"name": "IsCool", "port": "4"}])
        index = make_services_index(settings)

        # given
        with os.fdopen(self.fd, mode='w') as file:
            json.dump(settings, file)

        # given
        mock_liberator = mock_aws_class.return_value
        mock_liberator.describe_rules.return_value = [rule_to_revoke]

        # when
        main(args=["--profile", self.filename])

        # then
        mock_print.assert_has_calls([mock.call("Authorizing rules", [svc for svc in index], "to IP", IP),
                                     mock.call('-', group_id)])

        # then
        mock_liberator.describe_rules.assert_called_once_with(index, settings['config'])
        mock_liberator.authorize_rule.assert_called_once_with({'GroupId': group_id,
                                                               'IpPermissions': [make_rule('Monty IsCool', IP, port=4)]})
        mock_liberator.revoke_rule.assert_called_once_with(rule_to_revoke)

    @mock.patch('ip_liberator.__main__.whats_my_ip')
    def test_main__my_ip(self, mock_whats_my_ip, *_):
        # given
        with os.fdopen(self.fd, mode='w') as file:
            json.dump(make_settings(), file)

        # given
        my_ip = "1.2.3.4/32"

        # when
        main(args=["--profile", self.filename, "--my-ip", my_ip])

        # then
        mock_whats_my_ip.assert_called_once_with(my_ip)

    def test_main__ip_informed_at_service(self, mock_print, mock_aws_class):
        # given
        group_id = "sg-1"
        informed_ip = "1.2.3.4/32"
        operator = "Peter"
        services = [{"name": "HTTP", "port": "80"},
                    {"name": "SFTP", "port": "22", "ip": informed_ip}]

        # given
        descriptions = ["%s %s" % (operator, svc["name"]) for svc in services]
        settings = make_settings(operator=operator, services=services, security_groups=[group_id])
        services_index = make_services_index(settings)
        rule = next(make_rules(services_index, settings['config']))

        # given
        with os.fdopen(self.fd, mode='w') as file:
            json.dump(settings, file)

        # when
        main(args=["--profile", self.filename])

        # then
        mock_print.assert_has_calls([mock.call("Authorizing rule '%s' to IP %s" % (descriptions[0], IP)),
                                     mock.call("Authorizing rule '%s' to IP %s" % (descriptions[1], informed_ip)),
                                     mock.call('-', group_id)])

        # then
        mock_liberator = mock_aws_class.return_value
        mock_liberator.describe_rules.assert_called_once_with(services_index, settings['config'])
        mock_liberator.authorize_rule.assert_called_once_with(rule)


def make_settings(access_key: str = None, secret_key: str = None, region_name: str = None,
                  operator: str = None, services: list = None, security_groups: list = None):
    return {
        "credentials": {
            "access_key": access_key or '',
            "secret_key": secret_key or '',
            "region_name": region_name or '',
        },
        "config": {
            "operator": operator or '',
            "services": services or [{"name": "example", "port": "255"}],
            "security_groups": security_groups or ["sg-x"],
        }
    }
