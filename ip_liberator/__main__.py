import argparse
import json
import sys
import os.path

from . import __version__
from .ip_liberator import AwsIpLiberator
from .utils import whats_my_ip, make_rules, duplicate_removal


def main(program=sys.argv[0], args=sys.argv[1:]):
    parser = argparse.ArgumentParser(prog=os.path.basename(program), description='AWS IP Liberator')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-p', '--profile',
                        dest='settings', required=True, type=open, metavar='FILE',
                        help='Profile settings in JSON format')
    parser.add_argument('--operator',
                        dest='operator', required=False, default=None,
                        help='Override the operator informed in the config')
    parser.add_argument('--my-ip',
                        dest='my_ip', required=False, default=None,
                        help='Use this IP instead of discover current')
    parser.add_argument('-t', '--tag',
                        dest='tag', default='ip-liberator',
                        help='Help to identify entries added by IP Liberator on security group (default: %(default)s)')
    parser.add_argument('--no-tag', dest='tag', action='store_const', const=None, help=argparse.SUPPRESS)
    parser.add_argument('--revoke-only',
                        dest='revoke_only', action='store_true',
                        help='Only revoke the rules specified in the config')

    args = parser.parse_args(args)
    settings = json.load(args.settings)
    revoke_only = args.revoke_only

    if args.my_ip:
        whats_my_ip(args.my_ip)

    if args.operator:
        settings['config']['operator'] = args.operator

    if args.tag:
        print("[%s] tag used" % args.tag)
        settings['config']['tag'] = args.tag

    access_key = settings['credentials']['access_key']
    secret_key = settings['credentials']['secret_key']
    region_name = settings['credentials']['region_name']

    liberator = AwsIpLiberator(access_key, secret_key, region_name, tag=args.tag)

    # create index of services
    services = make_services_index(settings)

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


def make_services_index(settings):
    operator = settings['config']['operator']
    return {'%s %s' % (operator, svc['name']): svc for svc in settings['config']['services']}
