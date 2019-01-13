#!/usr/bin/env python

"""Tests for `ip_liberator` package."""
import typing
import unittest.mock

from unittest.mock import call

import botocore.exceptions
import pytest

from ip_liberator.ip_liberator import AwsIpLiberator

credentials = {'access_key': 'Gnawer Comade',
               'secret_key': '123456',
               'region_name': 'brazil-northeast'}


class TestAwsIpLiberator:
    def setup_method(self):
        with unittest.mock.patch('boto3.session.Session'):
            self.liberator = AwsIpLiberator(**credentials)

    def test_authorize_rule(self):
        # given
        mock_ec2 = self.liberator.ec2
        any_dict = {'a': 0, 'b': 1, 'c': 2}

        # when
        self.liberator.authorize_rule(any_dict)

        # then
        mock_ec2.authorize_security_group_ingress.assert_called_once_with(**any_dict)

    def test_authorize_rule__error_reraised(self):
        # given
        error = botocore.exceptions.ClientError(unittest.mock.NonCallableMagicMock(), 'test')
        mock_ec2 = self.liberator.ec2
        mock_ec2.authorize_security_group_ingress.side_effect = error

        # given
        any_dict = {'a': 0, 'b': 1, 'c': 2}

        # when..then
        with pytest.raises(botocore.exceptions.ClientError):
            self.liberator.authorize_rule(any_dict)

        # then
        mock_ec2.authorize_security_group_ingress.assert_called_once_with(**any_dict)

    @unittest.mock.patch('ip_liberator.ip_liberator.print')
    def test_authorize_rule__already_exists(self, mock_print):
        # given
        error = botocore.exceptions.ClientError({'Error': {'Code': 'InvalidPermission.Duplicate'}}, 'test')
        mock_ec2 = self.liberator.ec2
        mock_ec2.authorize_security_group_ingress.side_effect = error

        # given
        rule = {'IpPermissions': [{'IpRanges': [{'Description': 'Python is Cool', 'CidrIp': '1.2.3.4/8'}]}]}

        # when
        self.liberator.authorize_rule(rule)

        # then
        mock_ec2.authorize_security_group_ingress.assert_called_once_with(**rule)

        # then
        mock_print.assert_called_once_with(
            "> Rule 'Python is Cool' not set: permission with IP 1.2.3.4/8 already exists")

    def test_authorize_rule__authorized_individually(self):
        # given
        error = botocore.exceptions.ClientError({'Error': {'Code': 'InvalidPermission.Duplicate'}}, 'test')
        mock_ec2 = self.liberator.ec2
        mock_ec2.authorize_security_group_ingress.side_effect = (error, None, None)

        # given
        full_rule = {'GroupId': 'sg-1',
                     'IpPermissions': [{'IpRanges': [{'Description': 'Py3', 'CidrIp': '1.1.1.1/8'}]},
                                       {'IpRanges': [{'Description': '@->', 'CidrIp': '2.2.2.2/8'}]}]}
        rule1, rule2 = [{'GroupId': 'sg-1',
                         'IpPermissions': [p]} for p in full_rule['IpPermissions']]

        # when
        self.liberator.authorize_rule(full_rule)

        # then
        mock_ec2.authorize_security_group_ingress.assert_has_calls([call(**full_rule), call(**rule1), call(**rule2)])

    def test_revoke_rule(self):
        # given
        mock_ec2 = self.liberator.ec2

        # given
        any_dict = {'a': 0, 'b': 1, 'c': 2}

        # when
        self.liberator.revoke_rule(any_dict)

        # then
        mock_ec2.revoke_security_group_ingress.assert_called_once_with(**any_dict)

    def test_describe_rules(self):
        # given
        group_ids = ['sg-1', 'sg-2']
        services = ('SSH', 'HTTP')
        wanted = [{'Description': svc} for svc in services]

        # given
        def describe_rules_return(group_id: str, data: list) -> dict:
            return {'GroupId': group_id, 'IpPermissions': [{'IpRanges': data}]}

        # given
        unwanted = [{'Description': svc + '1'} for svc in services]
        aws_return = {'SecurityGroups': [describe_rules_return(group_ids[0], wanted),     # first is kept
                                         describe_rules_return(group_ids[1], unwanted)]}  # last is removed (unwanted)

        # given
        mock_ec2 = self.liberator.ec2
        mock_ec2.describe_security_groups.return_value = aws_return

        # when
        rules = self.liberator.describe_rules(services, {'security_groups': group_ids})

        # then
        assert isinstance(rules, typing.Iterator)

        # then
        assert next(rules) == describe_rules_return(group_ids[0], wanted)

        # then
        with pytest.raises(StopIteration):
            next(rules)

    @unittest.mock.patch('boto3.session.Session')
    def test_init(self, mock):
        # given
        mock_session = unittest.mock.NonCallableMock()
        mock.return_value = mock_session

        # when
        liberator = AwsIpLiberator(**credentials)

        # then
        assert liberator.ec2 == mock_session.client.return_value

        # then
        mock.assert_called_once_with(
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            region_name=credentials['region_name']
        )
        mock_session.client.assert_called_once_with('ec2')
