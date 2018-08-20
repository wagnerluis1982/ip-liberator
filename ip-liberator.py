import http.client
import sys
from typing import Sequence

import boto3
import botocore.exceptions

ACCESS_KEY = '<AWS ACCESS KEY>'
SECRET_KEY = '<AWS SECRET ACCESS KEY>'
REGION_NAME = '<AWS REGION>'
GROUP_ID = '<AWS GROUP ID>'

OPERATOR = 'Wagner'
SERVICES = [
    {
        'name': 'RDP',
        'port': '3389-3389',
    },
    {
        'name': 'HTTPS',
        'port': '443',
    },
]


def whats_my_ip():
    conn = http.client.HTTPSConnection("checkip.amazonaws.com")

    conn.request('GET', '/')
    response = conn.getresponse()

    if response.status == 200:
        data = response.read().strip()
        return "%s/32" % data.decode('utf8')

    return None


def has_port(rule: dict, *ports: int):
    return rule['FromPort'] in ports and rule['FromPort'] == rule['ToPort']


def make_rule(description: str, cidr_ip: str, ports: Sequence[int]):
    return {
        'FromPort': ports[0],
        'ToPort': ports[1],
        'IpProtocol': 'tcp',
        'IpRanges': [
            {
                'CidrIp': cidr_ip,
                'Description': description
            }
        ]
    }


def make_index(operator, services, group):
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
            description = ip_range['Description']
            if description in svc_index['rules']:
                svc_index['rules'][description]['permission'] = make_rule(description,
                                                                          ip_range['CidrIp'],
                                                                          ports=(
                                                                              ip_perm['FromPort'],
                                                                              ip_perm['ToPort'],
                                                                          ))

    return svc_index


def main():
    session = boto3.session.Session(aws_access_key_id=ACCESS_KEY,
                                    aws_secret_access_key=SECRET_KEY,
                                    region_name=REGION_NAME)
    ec2 = session.client('ec2')

    try:
        group = ec2.describe_security_groups(GroupIds=[GROUP_ID])['SecurityGroups'][0]
    except IndexError:
        print("Security group '%s' not found")
        return 1

    svc_index = make_index(OPERATOR, SERVICES, group)

    for desc, rule in svc_index['rules'].items():
        # remove previous rule if exists any
        if 'permission' in rule:
            ec2.revoke_security_group_ingress(
                GroupId=GROUP_ID,
                IpPermissions=[rule['permission']]
            )

        # permission to set new IP
        ip = rule['service'].get('ip') or whats_my_ip()
        ports = rule['service']['port']
        permission = make_rule(desc, ip, ports)

        try:
            ec2.authorize_security_group_ingress(
                GroupId=GROUP_ID,
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
