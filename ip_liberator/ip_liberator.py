"""Main module."""

import argparse
import http.client
import json
import sys
from functools import lru_cache

import boto3
import botocore.exceptions


@lru_cache(maxsize=1)
def whats_my_ip():
    conn = http.client.HTTPSConnection("checkip.amazonaws.com")

    conn.request('GET', '/')
    response = conn.getresponse()

    if response.status == 200:
        data = response.read().strip()
        return "%s/32" % data.decode('utf8')

    return None


def duplicate_removal(rule1, rule2):
    def mk_keys(rule):
        return {(ip_permission['FromPort'], ip_permission['ToPort'], ip_range['Description'], ip_range['CidrIp']): i
                for i, ip_permission in enumerate(rule['IpPermissions'])
                for ip_range in ip_permission['IpRanges']}

    rule_keys1 = mk_keys(rule1)
    rule_keys2 = mk_keys(rule2)

    indexes = [(rule_keys1[key], rule_keys2[key]) for key in rule_keys2 if key in rule_keys1]
    indexes = zip(sorted([t[0] for t in indexes], reverse=True),
                  sorted([t[1] for t in indexes], reverse=True))

    for i, j in indexes:
        del rule1['IpPermissions'][i]
        del rule2['IpPermissions'][j]


def make_rule(description: str, cidr_ip: str,
              *, port: int = None, from_port: int = None, to_port: int = None) -> dict:
    if port is not None:
        assert from_port is None and to_port is None, "cannot mix 'port' with 'from_port' and 'to_port'"
        from_port = to_port = port
    else:
        assert from_port is not None and to_port is not None, "port range not set"

    return {
        'FromPort': from_port,
        'ToPort': to_port,
        'IpProtocol': 'tcp',
        'IpRanges': [
            {
                'CidrIp': cidr_ip,
                'Description': description
            }
        ]
    }


def make_rules(services: dict, config: dict):
    group_ids = config['security_groups']

    ip_permissions = []
    for description, service in services.items():
        ip = service.get('ip') or whats_my_ip()

        port_range = service['port'].split('-')
        if not port_range or len(port_range) > 2:
            raise ValueError("Invalid port range: '%s'" % service['port'])

        port_range = tuple(map(int, port_range))
        if len(port_range) == 1:
            port_range *= 2

        ip_permissions += [make_rule(description, ip, from_port=port_range[0], to_port=port_range[1])]

    for gid in group_ids:
        yield {
            'GroupId': gid,
            'IpPermissions': ip_permissions[:]
        }


class AwsIpLiberator:
    """AWS IP Liberator

    :param access_key:  AWS access key
    :param secret_key:  AWS secret access key
    :param region_name: AWS region name
    """

    def __init__(self, access_key: str, secret_key: str, region_name: str):
        session = boto3.session.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region_name
        )
        self.ec2 = session.client('ec2')

    def authorize_rule(self, rule: dict):
        # rule authorization
        try:
            self.ec2.authorize_security_group_ingress(**rule)
        # in case of problems to authorize
        except botocore.exceptions.ClientError as e:
            # when a permission is duplicated
            if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                ip_permissions = rule['IpPermissions']

                # single duplicated permission: results in a warning
                if len(ip_permissions) == 1:
                    description, ip = (ip_permissions[0]['IpRanges'][0][k]
                                       for k in ('Description', 'CidrIp'))
                    print("> Rule '%s' not set: permission with IP %s already exists" % (description, ip))
                # several permissions: retry authorize permission by permission
                else:
                    for ip_perm in ip_permissions:
                        self.authorize_rule({'GroupId': rule['GroupId'],
                                             'IpPermissions': [ip_perm]})
            else:
                raise e

    def revoke_rule(self, rule: dict):
        self.ec2.revoke_security_group_ingress(**rule)

    def describe_rules(self, services: dict, config: dict):
        group_ids = config['security_groups']
        groups = self.ec2.describe_security_groups(GroupIds=group_ids)['SecurityGroups']

        for group in groups:
            group_id = group['GroupId']
            ip_permissions = group['IpPermissions'][:]

            for i in reversed(range(len(ip_permissions))):
                ip_perm = ip_permissions[i]
                ip_perm['IpRanges'] = [e for e in ip_perm['IpRanges']
                                       if 'Description' in e and e['Description'] in services]

                if not ip_perm['IpRanges']:
                    del ip_permissions[i]

            if not ip_permissions:
                continue

            yield {
                'GroupId': group_id,
                'IpPermissions': ip_permissions
            }




def main(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='AWS IP Liberator')
    parser.add_argument('--profile',
                        dest='settings', required=True, type=open,
                        help='Profile settings in JSON format')
    parser.add_argument('--my-ip',
                        dest='my_ip', required=False, default=None,
                        help='Use this IP instead of discover current')
    parser.add_argument('--revoke-only',
                        dest='revoke_only', action='store_true',
                        help='Only revoke the rules specified in the config')

    args = parser.parse_args(args)
    settings = json.load(args.settings)
    revoke_only = args.revoke_only

    if args.my_ip:
        global whats_my_ip
        whats_my_ip = lambda ip=args.my_ip: ip

    access_key = settings['credentials']['access_key']
    secret_key = settings['credentials']['secret_key']
    region_name = settings['credentials']['region_name']

    liberator = AwsIpLiberator(access_key, secret_key, region_name)

    # create index of services
    operator = settings['config']['operator']
    services = {'%s %s' % (operator, svc['name']): svc for svc in settings['config']['services']}

    # rules to revoke matching config entries
    revoking_rules = liberator.describe_rules(services, settings['config'])

    # don't authorize
    if revoke_only:
        print("Revoking rules", [svc for svc in services])
        for rule_to_revoke in revoking_rules:
            print('-', rule_to_revoke['GroupId'])
            liberator.revoke_rule(rule_to_revoke)

        return 0

    # when authorizing, make a index of the revoking rules
    revoking_rules = {rule['GroupId']: rule for rule in revoking_rules}

    # rules to authorize from groups and services in the config
    liberator_rules = make_rules(services, settings['config'])

    # use first rule to print ip addresses
    rule_to_authorize = next(liberator_rules)
    ip_addresses = set(ip_range['CidrIp']
                       for ip_permission in rule_to_authorize['IpPermissions']
                       for ip_range in ip_permission['IpRanges'])

    if len(ip_addresses) == 1:
        print("Authorizing rules", [svc for svc in services], "to IP", ip_addresses.pop())
    else:
        for ip_range in (r for p in rule_to_authorize['IpPermissions'] for r in p['IpRanges']):
            print("Authorizing rule '%s' to IP %s" % (ip_range['Description'], ip_range['CidrIp']))

    while True:
        group_id = rule_to_authorize['GroupId']
        print('-', group_id)

        # revoke rules in this security group if any
        rule_to_revoke = revoking_rules.get(group_id)

        if rule_to_revoke:
            duplicate_removal(rule_to_authorize, rule_to_revoke)

            if rule_to_revoke['IpPermissions']:
                liberator.revoke_rule(rule_to_revoke)

        # authorize rules with new ip
        if rule_to_authorize['IpPermissions']:
            liberator.authorize_rule(rule_to_authorize)

        try:
            rule_to_authorize = next(liberator_rules)
        except StopIteration:
            break

    return 0


if __name__ == "__main__":
    sys.exit(main())
