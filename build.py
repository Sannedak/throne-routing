#!/usr/bin/env python3
"""Strict Shadowrocket/RoscomVPN/Hxehex -> sing-box + Throne route profiles."""
import argparse
import base64
import collections
import csv
import datetime
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.parse
import urllib.request
import zipfile

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

    def data(self, url):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != 'https' or parsed.hostname not in ('api.github.com', 'raw.githubusercontent.com', 'github.com'):
            raise ValueError('Unapproved source URL: ' + url)
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
                        data = r.read(50_000_001)
                    if len(data) > 50_000_000:
                        raise ValueError('Source too large: ' + url)
                    break
                except (OSError, TimeoutError):
                    if attempt == 2:
                        raise
                    time.sleep(2 * (attempt + 1))
            self.cache.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.records[url] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        return data

    def get(self, url):
        return self.data(url).decode('utf-8-sig')

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
    config = {'dns': {'servers': [{'type': 'local', 'tag': 'local'}]}, 'outbounds': [{'type': 'direct', 'tag': 'direct'}, {'type': 'socks', 'tag': 'proxy', 'server': '127.0.0.1', 'server_port': 9}], 'route': {'default_domain_resolver': 'local', 'rules': rules, 'rule_set': list(definitions.values()), 'final': profile['default_outbound']}}
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
    build_shadow(sources, args, dist, manifest)
    manifest['compiler'] = subprocess.check_output([args.sing_box, 'version'], text=True).splitlines()[0]
    license_text = sources.file(MOBILE_REPO, mobile_sha, 'LICENSE')
    (dist / 'LICENSE-mobile.txt').write_text(license_text)
    geosite_repo, geosite_sha = refs['geosite']
    (dist / 'LICENSE-geosite.txt').write_text(sources.file(geosite_repo, geosite_sha, 'LICENSE'))
    manifest['sources'] = sources.records
    dump(dist / 'manifest.json', manifest)
    (dist / 'NOTICE.txt').write_text('Shadowrocket rules: https://github.com/misha-tgshv/shadowrocket-configuration-file\nExternal lists: https://github.com/blackmatrix7/ios_rule_script\nRelease lists: https://github.com/toneywhitez/zkeen_rules\nGeoIP and ASN: https://github.com/Loyalsoldier/geoip (GeoLite2 data created by MaxMind, https://www.maxmind.com)\nDerived routing data: https://github.com/hydraponique/roscomvpn-routing\nGeoSite: https://github.com/hydraponique/roscomvpn-geosite\nGeoIP: https://github.com/hydraponique/roscomvpn-geoip\nMobile: https://github.com/hxehex/russia-mobile-internet-whitelist\nSee source repositories for their respective terms. No blanket license is asserted for third-party data.\n')
    (dist / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in sorted(dist.iterdir()) if p.is_file()))
    print(json.dumps({'profiles': list(profiles), 'sets': len(converted), 'routing_commit': routing_sha, 'mobile_commit': mobile_sha}, indent=2))


SHADOW_REPO = 'misha-tgshv/shadowrocket-configuration-file'
BLACKMATRIX_REPO = 'blackmatrix7/ios_rule_script'
GEO_REPO = 'Loyalsoldier/geoip'
ZKEEN_REPO = 'toneywhitez/zkeen_rules'


def conf_sections(text):
    result, section = collections.defaultdict(list), None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if re.fullmatch(r'\[[A-Za-z ]+\]', line):
            section = line[1:-1]
        elif section is None:
            raise ValueError('Entry outside config section: ' + line)
        else:
            result[section].append(line)
    if set(result) - {'General', 'Rule'}:
        raise ValueError('Unreviewed active Shadowrocket section')
    return dict(result)


def asn_networks(data, wanted):
    result = {a: [] for a in wanted}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = [n for n in archive.namelist() if n.endswith(('GeoLite2-ASN-Blocks-IPv4.csv', 'GeoLite2-ASN-Blocks-IPv6.csv'))]
        if len(files) != 2 or sum(archive.getinfo(n).file_size for n in files) > 100_000_000:
            raise ValueError('Unexpected ASN archive')
        for name in files:
            with archive.open(name) as stream:
                for row in csv.DictReader(io.TextIOWrapper(stream, encoding='utf-8-sig')):
                    asn = row['autonomous_system_number']
                    if asn in result:
                        result[asn].append(str(ipaddress.ip_network(row['network'], strict=True)))
    # An ASN may have no current routes. Record this explicitly rather than inventing ranges.
    return result


def shadow_list(text, outer_no_resolve=False, asns=None):
    parts, resolve_flags, count = [], set(), 0
    asns = asns or {}
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        bits = [v.strip() for v in line.split(',')]
        if len(bits) == 1:
            try:
                ipaddress.ip_network(line, strict=True)
                bits = ['IP-CIDR', line]
            except ValueError:
                bits = ['DOMAIN', line]
        if len(bits) not in (2, 3) or (len(bits) == 3 and bits[2] != 'no-resolve'):
            raise ValueError('Unsupported list entry: ' + line)
        kind, value = bits[:2]
        no_resolve = outer_no_resolve or len(bits) == 3
        if kind in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'):
            if no_resolve:
                raise ValueError('no-resolve on domain entry: ' + line)
            field = {'DOMAIN': 'domain', 'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN-KEYWORD': 'domain_keyword'}[kind]
            if not value:
                raise ValueError('Empty domain match')
            parts.append({field: [domain(value) if kind != 'DOMAIN-KEYWORD' else value.lower()]})
        elif kind in ('IP-CIDR', 'IP-CIDR6', 'IP-ASN'):
            resolve_flags.add(not no_resolve)
            if kind == 'IP-ASN':
                if value not in asns:
                    raise ValueError('Unexpanded ASN: ' + value)
                if asns[value]:
                    parts.append(networks('\n'.join(asns[value])))
            else:
                parts.append(networks(value))
        else:
            raise ValueError('Unsupported list rule type: ' + kind)
        count += 1
    if not parts:
        raise ValueError('Empty converted rule set')
    if len(resolve_flags) > 1:
        raise ValueError('Mixed resolving and no-resolve IP entries need ordered conversion')
    return merge(parts), True in resolve_flags, count


def shadow_profile(name, entries, final, base):
    rules = [{'name': 'DNS interception', 'type': 'custom', 'protocol': 'dns', 'action': 'hijack-dns'}]
    resolved = False
    for key, policy, needs_resolve, has_ip in entries:
        if resolved and has_ip and not needs_resolve:
            raise ValueError('no-resolve after resolving rule needs manual review')
        if needs_resolve and not resolved:
            rules.append({'name': 'Resolve at first resolving IP rule', 'type': 'custom', 'action': 'resolve'})
            resolved = True
        rule = {'name': key + ' → ' + policy, 'type': 'custom', 'rule_set': [base + '/' + key + '.srs'], 'action': 'reject' if policy in ('REJECT', 'BLOCK') else 'route'}
        if rule['action'] == 'route':
            if policy not in ('PROXY', 'DIRECT'):
                raise ValueError('Unknown policy: ' + policy)
            rule['outbound'] = policy.lower()
        rules.append(rule)
    if final not in ('PROXY', 'DIRECT'):
        raise ValueError('Unsupported FINAL: ' + final)
    return {'kind': 'throne-route-profile', 'v': 1, 'name': name, 'default_outbound': final.lower(), 'rules': rules}


def build_shadow(sources, args, dist, manifest):
    pins = {repo: sources.sha(repo, ref) for repo, ref in ((SHADOW_REPO, 'main'), (BLACKMATRIX_REPO, 'master'), (GEO_REPO, 'release'), ('hydraponique/roscomvpn-geoip', 'master'), (MOBILE_REPO, 'main'))}
    report = {'commits': pins, 'profiles': {}, 'rule_sets': {}, 'scope': 'Active [Rule] sections of sr_ru_basic, sr_ru_geo and sr_ru_whitelist; General settings are not imported.'}
    configs = {}
    for mode in ('basic', 'geo', 'whitelist', 'extended'):
        text = sources.file(SHADOW_REPO, pins[SHADOW_REPO], f'conf/sr_ru_{mode}.conf')
        (dist / f'source-sr-ru-{mode}.conf').write_text(text)
        configs[mode] = conf_sections(text)
    if configs['extended'].get('Rule'):
        raise ValueError('Extended rules became non-empty; review include ordering before publishing')
    for mode in ('basic', 'geo', 'whitelist'):
        includes = [line for line in configs[mode].get('General', []) if line.split('=', 1)[0].strip() == 'include']
        if includes != ['include = sr_ru_extended.conf']:
            raise ValueError('Unexpected include: ' + str(includes))

    # Exact ASN expansion from the same publisher/database family recommended upstream.
    telegram = sources.file(BLACKMATRIX_REPO, pins[BLACKMATRIX_REPO], 'rule/Shadowrocket/Telegram/Telegram.list')
    wanted = set(re.findall(r'^IP-ASN,(\d+)(?:,no-resolve)?\s*$', telegram, re.M))
    archive = sources.data(f'https://raw.githubusercontent.com/{GEO_REPO}/{pins[GEO_REPO]}/GeoLite2-ASN-CSV.zip')
    asns = asn_networks(archive, wanted)
    report['asn_prefix_counts'] = {a: len(v) for a, v in sorted(asns.items())}

    release = json.loads(sources.get(f'https://api.github.com/repos/{ZKEEN_REPO}/releases/latest'))
    report['zkeen_release'] = {'id': release['id'], 'tag': release['tag_name'], 'assets': {}}
    converted, source_info = {}, {}

    def convert_url(url, no_resolve):
        cdn = re.fullmatch(r'https://cdn\.jsdelivr\.net/gh/(misha-tgshv/shadowrocket-configuration-file|blackmatrix7/ios_rule_script)@(main|master)/(.+)', url)
        asset = re.fullmatch(r'https://github\.com/toneywhitez/zkeen_rules/releases/latest/download/(telegram_ips|meta_ips)\.list', url)
        if cdn:
            repo, ref, path = cdn.groups()
            if (repo == SHADOW_REPO and ref != 'main') or (repo == BLACKMATRIX_REPO and ref != 'master'):
                raise ValueError('Unexpected source ref')
            text = sources.file(repo, pins[repo], path)
            key = 'sr-' + ('community-' if repo == SHADOW_REPO else 'blackmatrix-') + Path(path).stem.lower().replace('_', '-')
        elif asset:
            filename = asset[1] + '.list'
            found = [a for a in release['assets'] if a['name'] == filename]
            if len(found) != 1:
                raise ValueError('Missing release asset: ' + filename)
            entry = found[0]
            expected_url = f'https://github.com/{ZKEEN_REPO}/releases/download/{release["tag_name"]}/{filename}'
            if entry['browser_download_url'] != expected_url:
                raise ValueError('Unexpected release asset URL')
            data = sources.data(expected_url)
            digest = 'sha256:' + hashlib.sha256(data).hexdigest()
            if entry.get('digest') != digest:
                raise ValueError('Release asset checksum mismatch: ' + filename)
            report['zkeen_release']['assets'][filename] = digest
            text, key = data.decode('utf-8-sig'), 'sr-zkeen-' + asset[1].replace('_', '-')
        elif url == 'https://github.com/hydraponique/roscomvpn-geoip/raw/refs/heads/master/release/text/whitelist.txt':
            repo = 'hydraponique/roscomvpn-geoip'
            text = sources.file(repo, pins[repo], 'release/text/whitelist.txt')
            key = 'sr-roscom-whitelist-ips'
        elif url == 'https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt':
            text = sources.file(MOBILE_REPO, pins[MOBILE_REPO], 'whitelist.txt')
            key = 'sr-mobile-domains'
        else:
            raise ValueError('Unreviewed RULE-SET URL: ' + url)
        rule, resolves, count = shadow_list(text, no_resolve, asns)
        if key in converted and converted[key] != rule:
            raise ValueError('Conflicting rule set: ' + key)
        converted[key] = rule
        source_info[key] = {'upstream_url': url, 'source_entries': count, 'resolve': resolves}
        return key, resolves, 'ip_cidr' in rule

    base = f'https://raw.githubusercontent.com/{args.repository}/rules'
    profiles = {}
    for mode in ('basic', 'geo', 'whitelist'):
        entries, final = [], None
        for line in configs[mode].get('Rule', []):
            if final is not None:
                raise ValueError('Rules after FINAL: ' + line)
            bits = [b.strip() for b in line.split(',')]
            if bits[0] == 'FINAL' and len(bits) == 2:
                final = bits[1]
            elif bits[0] == 'RULE-SET' and len(bits) in (3, 4):
                if len(bits) == 4 and bits[3] != 'no-resolve':
                    raise ValueError('Unknown RULE-SET flag: ' + line)
                key, resolves, has_ip = convert_url(bits[1], len(bits) == 4)
                entries.append((key, bits[2], resolves, has_ip))
            elif bits[0] == 'GEOIP' and len(bits) == 3 and bits[1] == 'RU':
                key = 'sr-geoip-ru'
                converted[key] = networks(sources.file(GEO_REPO, pins[GEO_REPO], 'text/ru.txt'))
                source_info[key] = {'database': 'Loyalsoldier/geoip Country-without-asn family', 'resolve': True}
                entries.append((key, bits[2], True, True))
            else:
                raise ValueError('Unreviewed active config rule: ' + line)
        profiles['sr-ru-' + mode] = shadow_profile('sr-ru-' + mode, entries, final, base)
        report['profiles']['sr-ru-' + mode] = {'source_rules': configs[mode]['Rule'], 'final': final}
    for key, rule in converted.items():
        source, target = dist / (key + '.json'), dist / (key + '.srs')
        dump(source, {'version': 3, 'rules': [rule]})
        subprocess.run([args.sing_box, 'rule-set', 'compile', '--output', str(target), str(source)], check=True)
        decoded = dist.parent / (key + '.decoded.json')
        subprocess.run([args.sing_box, 'rule-set', 'decompile', '--output', str(decoded), str(target)], check=True)
        if not json.loads(decoded.read_text())['rules']:
            raise ValueError('Empty compiled rules: ' + key)
        report['rule_sets'][key] = dict(source_info[key], counts={k: len(v) for k, v in rule.items()})
    for name, profile in profiles.items():
        dump(dist / (name + '.route.json'), profile)
        validate_profile(profile, dist, args.sing_box)
        link = 'throne://remoteroute/' + base64.urlsafe_b64encode((base + '/' + name + '.route.json#' + name).encode()).decode().rstrip('=')
        (dist / (name + '.import.txt')).write_text(link + '\n')
    report['limitations'] = [
        'Not a complete Shadowrocket configuration: DNS, IPv6, skip-proxy, TUN exclusions, proxy groups, MITM and modules are not imported.',
        'no-resolve means no added resolve action; existing IP metadata from TUN/DNS/sniffing can still match.',
        'Bare mobile hostnames are exact matches, not suffixes. GEOIP is a dated database snapshot.',
        'Legacy roscom-* profiles remain available unchanged in meaning; select sr-ru-* for Shadowrocket behavior.'
    ]
    manifest['shadowrocket'] = report
    manifest['limitations_scope'] = 'Top-level limitations apply to legacy roscom-*; see shadowrocket.limitations for sr-ru-*.'
    print(json.dumps({'shadowrocket_profiles': list(profiles), 'sets': len(converted), 'asn_prefix_counts': report['asn_prefix_counts']}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--sing-box', default='sing-box')
    parser.add_argument('--output', default='dist')
    parser.add_argument('--cache', default='.source-cache')
    parser.add_argument('--repository', default='Sannedak/throne-routing')
    build(parser.parse_args())
