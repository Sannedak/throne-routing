import unittest
import io
import zipfile
import build


class ConversionTests(unittest.TestCase):
    def test_domain_semantics(self):
        result = build.geosite('example.com\nfull:one.example.com\nkeyword:needle\nregexp:^X[0-9]\\.example$\ndomain:EXAMPLE.org @ads # comment')
        self.assertEqual(result['domain_suffix'], ['example.com', 'example.org'])
        self.assertEqual(result['domain'], ['one.example.com'])
        self.assertEqual(result['domain_keyword'], ['needle'])
        self.assertEqual(result['domain_regex'], ['^X[0-9]\\.example$'])

    def test_unknown_or_empty_fails(self):
        for text in ('include:other', 'unknown:example.com', '# empty', 'domain:'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                build.geosite(text)

    def test_mobile_does_not_widen_sni_to_subdomains(self):
        self.assertEqual(build.mobile_domains('Example.com\nexample.com\n'), {'domain': ['example.com']})

    def test_ip_collapse_and_validation(self):
        self.assertEqual(build.networks('192.0.2.0/25\n192.0.2.128/25\n2001:db8::1'), {'ip_cidr': ['192.0.2.0/24', '2001:db8::1/128']})
        for text in ('192.0.2.1/24', '<html>error</html>', ''):
            with self.subTest(text=text), self.assertRaises(ValueError):
                build.networks(text)

    def test_priorities_and_domain_before_ip(self):
        groups = {(p, t): [p.lower() + '-' + t] for p in build.ORDER for t in ('sites', 'ip')}
        result = build.make_profile('test', groups, 'https://example.org')
        names = [r['name'] for r in result['rules']]
        self.assertEqual(names[1:4], ['BLOCK sites', 'PROXY sites', 'DIRECT sites'])
        self.assertEqual(names[5:], ['BLOCK ip', 'PROXY ip', 'DIRECT ip'])
        self.assertEqual(result['rules'][4]['action'], 'resolve')
        self.assertEqual(result['default_outbound'], 'proxy')
        self.assertEqual(result['rules'][1]['action'], 'reject')
        self.assertNotIn('outbound', result['rules'][1])

    def test_unexpected_source_url_fails(self):
        with self.assertRaises(ValueError):
            build.database_ref('https://example.org/geoip.dat', 'hydraponique/roscomvpn-geoip')

    def test_shadowrocket_exact_suffix_keyword_and_no_resolve(self):
        rule, resolves, count = build.shadow_list('DOMAIN,ONE.EXAMPLE\nDOMAIN-SUFFIX,example.org\nDOMAIN-KEYWORD,needle\nIP-CIDR,192.0.2.0/24,no-resolve\nIP-ASN,123,no-resolve', asns={'123': ['2001:db8::/32']})
        self.assertEqual(rule['domain'], ['one.example'])
        self.assertEqual(rule['domain_suffix'], ['example.org'])
        self.assertEqual(rule['domain_keyword'], ['needle'])
        self.assertEqual(set(rule['ip_cidr']), {'192.0.2.0/24', '2001:db8::/32'})
        self.assertFalse(resolves)
        self.assertEqual(count, 5)

    def test_shadowrocket_bare_lists_and_resolution(self):
        self.assertEqual(build.shadow_list('host.example')[0], {'domain': ['host.example']})
        self.assertTrue(build.shadow_list('192.0.2.1')[1])
        self.assertFalse(build.shadow_list('192.0.2.1', True)[1])

    def test_shadowrocket_rejects_silent_losses(self):
        for value in ('IP-ASN,123', 'DST-PORT,443', 'DOMAIN,a.example,PROXY', 'IP-CIDR,192.0.2.0/24\nIP-CIDR,198.51.100.0/24,no-resolve', '<html>error</html>'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build.shadow_list(value)
        with self.assertRaises(ValueError):
            build.conf_sections('[Rule]\nFINAL,DIRECT\n[Script]\nx=y')

    def test_shadowrocket_source_order_and_defaults(self):
        entries = [('exception', 'PROXY', False, False), ('ru', 'DIRECT', True, True), ('checker', 'DIRECT', False, False), ('blocked', 'REJECT', False, False)]
        profile = build.shadow_profile('geo', entries, 'PROXY', 'https://example.org')
        self.assertEqual([r['action'] for r in profile['rules']], ['hijack-dns', 'route', 'resolve', 'route', 'route', 'reject'])
        self.assertEqual(profile['rules'][1]['outbound'], 'proxy')
        self.assertEqual(profile['rules'][3]['outbound'], 'direct')
        basic = build.shadow_profile('basic', [('ips', 'PROXY', False, True)], 'DIRECT', 'https://example.org')
        self.assertEqual(basic['default_outbound'], 'direct')
        self.assertNotIn('resolve', [r['action'] for r in basic['rules']])
        with self.assertRaises(ValueError):
            build.shadow_profile('bad', [('first', 'DIRECT', True, True), ('later', 'PROXY', False, True)], 'PROXY', 'https://example.org')

    def test_asn_expansion_filters_both_families(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            header = 'network,autonomous_system_number,autonomous_system_organization\n'
            archive.writestr('GeoLite2-ASN-Blocks-IPv4.csv', header + '192.0.2.0/24,123,Test\n198.51.100.0/24,456,Other\n')
            archive.writestr('GeoLite2-ASN-Blocks-IPv6.csv', header + '2001:db8::/32,123,Test\n')
        self.assertEqual(build.asn_networks(data.getvalue(), {'123', '789'}), {'123': ['192.0.2.0/24', '2001:db8::/32'], '789': []})


if __name__ == '__main__':
    unittest.main()
