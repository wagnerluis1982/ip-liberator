import re
import urllib.request

from typing import Optional, Iterator


def whats_my_ip(my_ip: str = None) -> Optional[str]:
    # change cached value and return
    if my_ip:
        whats_my_ip.cache = my_ip
        return my_ip

    # try to return cached value
    try:
        return whats_my_ip.cache
    except AttributeError:
        pass

    with urllib.request.urlopen("https://checkip.amazonaws.com/") as response:
        if response.status == 200:
            data = response.read().strip()
            my_ip = "%s/32" % data.decode()
            return whats_my_ip(my_ip)

    return None


def make_keys(rule: dict) -> dict:
    return {(ip_permission['FromPort'], ip_permission['ToPort'], ip_range['Description'], ip_range['CidrIp']): i
            for i, ip_permission in enumerate(rule['IpPermissions'])
            for ip_range in ip_permission['IpRanges']}


def duplicate_removal(rule1: dict, rule2: dict) -> None:
    rule_keys1 = make_keys(rule1)
    rule_keys2 = make_keys(rule2)

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


RE_PORT_RANGE = re.compile(r"^[0-9]+(-[0-9]+)?$")


def make_rules(services: dict, config: dict) -> Iterator[dict]:
    group_ids = config['security_groups']

    ip_permissions = []
    for description, service in services.items():
        ip = service.get('ip') or whats_my_ip()
        port_spec = service['port'].strip()

        if not port_spec:
            raise ValueError("No port range informed in service: %s" % description)

        if not RE_PORT_RANGE.match(port_spec):
            raise ValueError("Invalid port range: '%s'" % port_spec)

        port_range = tuple(map(int, port_spec.split('-')))
        if len(port_range) == 1:
            port_range *= 2

        ip_permissions += [make_rule(description, ip, from_port=port_range[0], to_port=port_range[1])]

    for gid in group_ids:
        yield {
            'GroupId': gid,
            'IpPermissions': ip_permissions[:]
        }
