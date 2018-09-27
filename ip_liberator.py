import argparse
import http.client
import json
import sys
from functools import lru_cache
from typing import Sequence

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


def has_port(rule: dict, *ports: int) -> bool:
    return rule['FromPort'] in ports and rule['FromPort'] == rule['ToPort']


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


def make_index(operator: str, services: Sequence[dict], group: dict):
    # firstly, create index from user-informed parameters!
    svc_index = {
        'rules': {},
    }

    for svc in services:
        description = '%s %s' % (operator, svc['name'])

        svc = svc.copy()
        if svc['port'].isdigit():
            port = int(svc['port'])
            svc['port'] = (port, port)
        else:
            port_range = svc['port'].split('-')
            if len(port_range) != 2:
                raise ValueError("Invalid port range: '%s'" % svc['port'])
            svc['port'] = tuple(map(int, port_range))

        svc_index['rules'][description] = {
            'service': svc,
        }

    # following, update index from Amazon security group
    for ip_perm in group['IpPermissions']:
        for ip_range in ip_perm['IpRanges']:
            description = ip_range.get('Description')
            if description in svc_index['rules']:
                svc_index['rules'][description]['permission'] = make_rule(description, ip_range['CidrIp'],
                                                                          from_port=ip_perm['FromPort'],
                                                                          to_port=ip_perm['ToPort'])

    return svc_index


def main(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='AWS IP Liberator')
    parser.add_argument('--profile',
                        dest='settings', required=True, type=open,
                        help='Profile settings in JSON format')
    parser.add_argument('--my-ip',
                        dest='my_ip', required=False, default=None,
                        help='Use this IP instead of discover current')

    args = parser.parse_args(args)
    settings = json.load(args.settings)

    if args.my_ip:
        global whats_my_ip
        whats_my_ip = lambda ip=args.my_ip: ip

    access_key = settings['credentials']['access_key']
    secret_key = settings['credentials']['secret_key']
    region_name = settings['credentials']['region_name']

    operator = settings['config']['operator']
    services = settings['config']['services']
    security_groups = settings['config']['security_groups']

    session = boto3.session.Session(aws_access_key_id=access_key,
                                    aws_secret_access_key=secret_key,
                                    region_name=region_name)
    ec2 = session.client('ec2')

    for group_id in security_groups:
        print("Entering security group", group_id)

        try:
            group = ec2.describe_security_groups(GroupIds=[group_id])['SecurityGroups'][0]
        except IndexError:
            print("Security group '%s' not found" % group_id, file=sys.stderr)
            return 1

        svc_index = make_index(operator, services, group)

        for desc, rule in svc_index['rules'].items():
            # remove previous rule if exists any
            if 'permission' in rule:
                ec2.revoke_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=[rule['permission']]
                )

            # permission to set new IP
            ip = rule['service'].get('ip') or whats_my_ip()
            ports = rule['service']['port']
            permission = make_rule(desc, ip, from_port=ports[0], to_port=ports[1])

            try:
                ec2.authorize_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=[permission]
                )
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                    print("Rule '%s' not set: permission using IP %s already exists" % (desc, ip))
                else:
                    raise e
            else:
                print("Updated rule '%s' to IP %s" % (desc, ip))

    return 0


if __name__ == "__main__":
    sys.exit(main())
