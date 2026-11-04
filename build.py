#!/usr/bin/env python3
"""Strict, reproducible RoscomVPN/Hxehex -> sing-box + Throne route profiles."""
import argparse
import base64
import collections
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
ORDER = ('Block', 'Proxy', 'Direct')
FIELDS = {'domain': 'domain_suffix', 'full': 'domain', 'keyword': 'domain_keyword', 'regexp': 'domain_regex'}
SOURCE_REPO = 'hydraponique/roscomvpn-routing'
MOBILE_REPO = 'hxehex/russia-mobile-internet-whitelist'


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


class Sources:
    def __init__(self, cache):
        self.cache = cache
        self.records = {}

    def get(self, url):
        assert urllib.parse.urlparse(url).hostname in ('api.github.com', 'raw.githubusercontent.com')
        key = hashlib.sha256(url.encode()).hexdigest()
        path = self.cache / key
        if path.exists():
            data = path.read_bytes()
        else:
            headers = {'User-Agent': 'throne-routing-builder'}
            if url.startswith('https://api.github.com/') and os.getenv('GH_TOKEN'):
                headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
                        data = r.read(25_000_001)
                    if len(data) > 25_000_000:
                        raise ValueError('Source too large: ' + url)
                    break
                except (OSError, TimeoutError):
                    if attempt == 2:
                        raise
                    time.sleep(2 * (attempt + 1))
            self.cache.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.records[url] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        return data.decode('utf-8-sig')

    def sha(self, repo, ref='HEAD'):
        data = json.loads(self.get(f'https://api.github.com/repos/{repo}/commits/{urllib.parse.quote(ref, safe="")}'))
        sha = data['sha']
        assert re.fullmatch('[0-9a-f]{40}', sha)
        return sha

    def file(self, repo, sha, path):
        return self.get(f'https://raw.githubusercontent.com/{repo}/{sha}/{path}')


def domain(value):
    value = value.rstrip('.').lower().encode('idna').decode('ascii')
    if len(value) > 253 or not value or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?', s) for s in value.split('.')):
        raise ValueError('Invalid domain: ' + value)
    return value


def geosite(text):
    result = collections.defaultdict(set)
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        bits = line.split()
        if any(not re.fullmatch(r'@[A-Za-z0-9_!.-]+', v) for v in bits[1:]):
            raise ValueError('Unsupported attributes: ' + line)
        token = bits[0]
        kind, value = token.split(':', 1) if ':' in token else ('domain', token)
        if kind not in FIELDS:
            # Includes/selectors must be implemented explicitly if upstream starts using them.
            raise ValueError('Unsupported GeoSite syntax: ' + line)
        if not value:
            raise ValueError('Empty GeoSite value')
        if kind in ('domain', 'full'):
            value = domain(value)
        result[FIELDS[kind]].add(value)
    if not result:
        raise ValueError('Empty GeoSite source')
    return {k: sorted(v) for k, v in sorted(result.items())}


def networks(text):
    values = set()
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            values.add(ipaddress.ip_network(line, strict=True))
    if not values:
        raise ValueError('Empty IP source')
    collapsed = []
    for family in (4, 6):
        collapsed += list(ipaddress.collapse_addresses(n for n in values if n.version == family))
    return {'ip_cidr': [str(n) for n in collapsed]}


def mobile_domains(text):
    # An observed SNI hostname does not imply all its subdomains are allowed.
    values = {domain(s.strip()) for s in text.splitlines() if s.strip() and not s.lstrip().startswith('#')}
    if not values:
        raise ValueError('Empty mobile domain source')
    return {'domain': sorted(values)}


def merge(parts):
    result = collections.defaultdict(set)
    for part in parts:
        for key, values in part.items():
            result[key].update(values)
    return {k: sorted(v) for k, v in sorted(result.items()) if v}


def database_ref(url, expected):
    match = re.fullmatch(r'https://cdn\.jsdelivr\.net/gh/(hydraponique/roscomvpn-(?:geoip|geosite))@([A-Za-z0-9._-]+)/release/(geoip|geosite)\.dat', url)
    if not match or match[1] != expected:
        raise ValueError('Unexpected database URL: ' + url)
    return match[2]


def check_config(config):
    allowed = {'Name', 'GlobalProxy', 'UseChunkFiles', 'RemoteDns', 'DomesticDns', 'RemoteDNSType', 'RemoteDNSDomain', 'RemoteDNSIP', 'DomesticDNSType', 'DomesticDNSDomain', 'DomesticDNSIP', 'Geoipurl', 'Geositeurl', 'LastUpdated', 'DnsHosts', 'RouteOrder', 'DomainStrategy', 'FakeDNS'}
    allowed.update(k + suffix for k in ORDER for suffix in ('Sites', 'Ip'))
    unknown = set(config) - allowed
    if unknown:
        raise ValueError('Unreviewed Happ settings: ' + str(unknown))
    if config['RouteOrder'] != 'block-proxy-direct' or config['GlobalProxy'] != 'true' or config['DomainStrategy'] != 'IPIfNonMatch' or config['FakeDNS'] != 'false':
        raise ValueError('Upstream routing semantics changed; review before publishing')


def make_profile(name, groups, base_url):
    rules = [{'name': 'DNS interception', 'type': 'custom', 'protocol': 'dns', 'action': 'hijack-dns'}]
    for phase in ('sites', 'ip'):
        if phase == 'ip' and any(groups.get((p, phase)) for p in ORDER):
            rules.append({'name': 'Resolve after domain rules (IPIfNonMatch approximation)', 'type': 'custom', 'action': 'resolve'})
        for policy in ORDER:
            names = groups.get((policy, phase), [])
            if not names:
                continue
            rule = {'name': f'{policy.upper()} {phase}', 'type': 'custom', 'rule_set': [base_url + '/' + n + '.srs' for n in names], 'action': 'reject' if policy == 'Block' else 'route'}
            if policy != 'Block':
                rule['outbound'] = policy.lower()
            rules.append(rule)
    return {'kind': 'throne-route-profile', 'v': 1, 'name': name, 'default_outbound': 'proxy', 'rules': rules}


def validate_profile(profile, dist, binary):
    # Validate the actual routing actions and compiled rule-sets with sing-box.
    # The proxy below is a loopback placeholder used for syntax validation only.
    rules, definitions = [], {}
    for original in profile['rules']:
        rule = {k: v for k, v in original.items() if k not in ('name', 'type')}
        if 'rule_set' in rule:
            tags = []
            for url in rule['rule_set']:
                filename = url.rsplit('/', 1)[1]
                tag = filename[:-4]
                assert filename.endswith('.srs') and (dist / filename).is_file()
                definitions[tag] = {'type': 'local', 'tag': tag, 'format': 'binary', 'path': str((dist / filename).resolve())}
                tags.append(tag)
            rule['rule_set'] = tags
        rules.append(rule)
    config = {'dns': {'servers': [{'type': 'local', 'tag': 'local'}]}, 'outbounds': [{'type': 'direct', 'tag': 'direct'}, {'type': 'socks', 'tag': 'proxy', 'server': '127.0.0.1', 'server_port': 9}], 'route': {'default_domain_resolver': 'local', 'rules': rules, 'rule_set': list(definitions.values()), 'final': 'proxy'}}
    check = dist.parent / 'check-config.json'
    dump(check, config)
    subprocess.run([binary, 'check', '-c', str(check)], check=True)


def build(args):
    sources = Sources(Path(args.cache))
    routing_sha = sources.sha(SOURCE_REPO)
    mobile_sha = sources.sha(MOBILE_REPO)
    configs = {name: json.loads(sources.file(SOURCE_REPO, routing_sha, 'HAPP/' + name + '.JSON')) for name in ('DEFAULT', 'WHITELIST')}
    dist = Path(args.output)
    dist.mkdir(parents=True, exist_ok=True)
    if any(dist.iterdir()):
        raise ValueError('Output directory must be empty (prevents publishing stale rules)')
    manifest = {'built_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'routing_commit': routing_sha, 'mobile_commit': mobile_sha, 'database_commits': {}, 'rule_sets': {}, 'limitations': ['Routing-only migration; not a complete Happ/INCY/Mihomo configuration.', 'DNS servers, DnsHosts, FakeDNS and client-specific settings are not imported.', 'IPIfNonMatch is approximated by domain rules, then resolve, then IP rules; Android DNS/sniffing can change available metadata.', 'Mobile list uses exact SNI hostnames; it cannot make a blocked VPN server reachable.']}
    converted = {}
    profiles = {}
    for name, config in configs.items():
        check_config(config)
        refs = {}
        for kind, key in [('geosite', 'Geositeurl'), ('geoip', 'Geoipurl')]:
            repo = 'hydraponique/roscomvpn-' + kind
            ref = database_ref(config[key], repo)
            sha = sources.sha(repo, ref)
            refs[kind] = (repo, sha)
            manifest['database_commits'][repo + '@' + ref] = sha
        groups = {}
        for policy in ORDER:
            for suffix, phase, kind in [('Sites', 'sites', 'geosite'), ('Ip', 'ip', 'geoip')]:
                parts = []
                for token in config[policy + suffix]:
                    if not re.fullmatch(kind + r':[a-z0-9_-]+', token):
                        raise ValueError('Unsupported Happ entry: ' + token)
                    category = token.split(':')[1]
                    repo, sha = refs[kind]
                    path = 'data/' + category if kind == 'geosite' else 'release/text/' + category + '.txt'
                    data = sources.file(repo, sha, path)
                    parts.append(geosite(data) if kind == 'geosite' else networks(data))
                if parts:
                    key = f'roscom-{name.lower()}-{policy.lower()}-{phase}'
                    converted[key] = merge(parts)
                    groups[(policy, phase)] = [key]
        profiles['roscom-' + name.lower()] = groups
        dump(dist / ('source-happ-' + name.lower() + '.json'), config)
    converted['mobile-domains'] = mobile_domains(sources.file(MOBILE_REPO, mobile_sha, 'whitelist.txt'))
    converted['mobile-ips'] = networks(sources.file(MOBILE_REPO, mobile_sha, 'ipwhitelist.txt') + '\n' + sources.file(MOBILE_REPO, mobile_sha, 'cidrwhitelist.txt'))
    combined = {k: list(v) for k, v in profiles['roscom-default'].items()}
    combined.setdefault(('Direct', 'sites'), []).append('mobile-domains')
    combined.setdefault(('Direct', 'ip'), []).append('mobile-ips')
    profiles['roscom-mobile'] = combined
    for key, rule in converted.items():
        source = dist / (key + '.json')
        target = dist / (key + '.srs')
        dump(source, {'version': 3, 'rules': [rule]})
        subprocess.run([args.sing_box, 'rule-set', 'compile', '--output', str(target), str(source)], check=True)
        # An independent decode catches broken or unreadable binaries.
        decoded = dist.parent / (key + '.decoded.json')
        subprocess.run([args.sing_box, 'rule-set', 'decompile', '--output', str(decoded), str(target)], check=True)
        assert json.loads(decoded.read_text())['rules']
        manifest['rule_sets'][key] = {k: len(v) for k, v in rule.items()}
    base = f'https://raw.githubusercontent.com/{args.repository}/rules'
    for name, groups in profiles.items():
        profile = make_profile(name, groups, base)
        dump(dist / (name + '.route.json'), profile)
        validate_profile(profile, dist, args.sing_box)
        link = 'throne://remoteroute/' + base64.urlsafe_b64encode((base + '/' + name + '.route.json#' + name).encode()).decode().rstrip('=')
        (dist / (name + '.import.txt')).write_text(link + '\n')
    manifest['compiler'] = subprocess.check_output([args.sing_box, 'version'], text=True).splitlines()[0]
    license_text = sources.file(MOBILE_REPO, mobile_sha, 'LICENSE')
    (dist / 'LICENSE-mobile.txt').write_text(license_text)
    geosite_repo, geosite_sha = refs['geosite']
    (dist / 'LICENSE-geosite.txt').write_text(sources.file(geosite_repo, geosite_sha, 'LICENSE'))
    manifest['sources'] = sources.records
    dump(dist / 'manifest.json', manifest)
    (dist / 'NOTICE.txt').write_text('Derived routing data: https://github.com/hydraponique/roscomvpn-routing\nGeoSite: https://github.com/hydraponique/roscomvpn-geosite\nGeoIP: https://github.com/hydraponique/roscomvpn-geoip\nMobile: https://github.com/hxehex/russia-mobile-internet-whitelist\nSee source repositories for their respective terms. No blanket license is asserted for third-party data.\n')
    (dist / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in sorted(dist.iterdir()) if p.is_file()))
    print(json.dumps({'profiles': list(profiles), 'sets': len(converted), 'routing_commit': routing_sha, 'mobile_commit': mobile_sha}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--sing-box', default='sing-box')
    parser.add_argument('--output', default='dist')
    parser.add_argument('--cache', default='.source-cache')
    parser.add_argument('--repository', default='Sannedak/throne-routing')
    build(parser.parse_args())
