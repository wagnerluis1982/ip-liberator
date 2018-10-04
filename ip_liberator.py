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


def describe_rules(ec2, services: dict, config: dict):
    group_ids = config['security_groups']
    groups = ec2.describe_security_groups(GroupIds=group_ids)['SecurityGroups']

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
            'IpPermissions': ip_permissions
        }


def revoke_rule(ec2, rule):
    ec2.revoke_security_group_ingress(**rule)

    for ip_range in (r for p in rule['IpPermissions'] for r in p['IpRanges']):
        print("Revoked rule '%s'" % ip_range['Description'])


def authorize_rule(ec2, rule):
    try:
        ec2.authorize_security_group_ingress(**rule)

        for ip_range in (r for p in rule['IpPermissions'] for r in p['IpRanges']):
            print("Authorized rule '%s' to IP %s" % (ip_range['Description'], ip_range['CidrIp']))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] != 'InvalidPermission.Duplicate':
            print(e)
        else:
            raise e


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

    session = boto3.session.Session(aws_access_key_id=access_key,
                                    aws_secret_access_key=secret_key,
                                    region_name=region_name)
    ec2 = session.client('ec2')

    # create index of services
    operator = settings['config']['operator']
    services = {'%s %s' % (operator, svc['name']): svc for svc in settings['config']['services']}

    # rules to revoke matching config entries
    revoking_rules = describe_rules(ec2, services, settings['config'])

    # don't authorize
    if revoke_only:
        for rule_to_revoke in revoking_rules:
            print("Security Group:", rule_to_revoke['GroupId'])
            revoke_rule(ec2, rule_to_revoke)

        return 0

    # when authorizing, make a index of the revoking rules
    revoking_rules = {rule['GroupId']: rule for rule in revoking_rules}

    # rules to authorize from groups and services in the config
    liberator_rules = make_rules(services, settings['config'])

    for rule_to_authorize in liberator_rules:
        group_id = rule_to_authorize['GroupId']
        print("Security Group:", group_id)

        # revoke rules in this security group if any
        rule_to_revoke = revoking_rules.get(group_id)

        if rule_to_revoke:
            revoke_rule(ec2, rule_to_revoke)

        # authorize rules with new ip
        authorize_rule(ec2, rule_to_authorize)

    return 0


if __name__ == "__main__":
    sys.exit(main())
