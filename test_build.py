import unittest
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


if __name__ == '__main__':
    unittest.main()
