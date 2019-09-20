"""Main module."""

import boto3
import botocore.exceptions


class AwsIpLiberator:
    """AWS IP Liberator

    :param access_key:  AWS access key
    :param secret_key:  AWS secret access key
    :param region_name: AWS region name
    """

    def __init__(self, access_key: str, secret_key: str, region_name: str, tag: str = None):
        session = boto3.session.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region_name
        )
        self.ec2 = session.client('ec2')
        self.tag = tag

    def authorize_rule(self, rule: dict):
        # rule authorization
        try:
            self.ec2.authorize_security_group_ingress(**self.tagged_rule(rule))
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
        if 'tag' in config:
            services = {'[%s] %s' % (config['tag'], key): value for key, value in services.items()}
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

    def tagged_rule(self, rule: dict) -> dict:
        if not self.tag:
            return rule

        new_rule = {
            **rule,
            'IpPermissions': [
                {
                    **ip_permission,
                    'IpRanges': [
                        {
                            **ip_range,
                            'Description': self.tag_description(ip_range['Description'])
                        }
                        for ip_range in ip_permission['IpRanges']]
                }
                for ip_permission in rule['IpPermissions']
            ]
        }
        return new_rule

    def tag_description(self, description: str):
        return description if not self.tag else '[%s] %s' % (self.tag, description)
