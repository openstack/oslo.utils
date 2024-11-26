# Copyright 2012 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from collections import namedtuple
import contextlib
import io
import socket
from unittest import mock

import netaddr
from oslotest import base as test_base

from oslo_utils import netutils


class NetworkUtilsTest(test_base.BaseTestCase):

    def test_no_host(self):
        result = netutils.urlsplit('http://')
        self.assertEqual('', result.netloc)
        self.assertIsNone(result.port)
        self.assertIsNone(result.hostname)
        self.assertEqual('http', result.scheme)

    def test_parse_host_port(self):
        self.assertEqual(('server01', 80),
                         netutils.parse_host_port('server01:80'))
        self.assertEqual(('server01', None),
                         netutils.parse_host_port('server01'))
        self.assertEqual(('server01', 1234),
                         netutils.parse_host_port('server01',
                         default_port=1234))
        self.assertEqual(('::1', 80),
                         netutils.parse_host_port('[::1]:80'))
        self.assertEqual(('::1', None),
                         netutils.parse_host_port('[::1]'))
        self.assertEqual(('::1', 1234),
                         netutils.parse_host_port('[::1]',
                         default_port=1234))
        self.assertEqual(('2001:db8:85a3::8a2e:370:7334', 1234),
                         netutils.parse_host_port(
                             '2001:db8:85a3::8a2e:370:7334',
                             default_port=1234))

    def test_urlsplit(self):
        result = netutils.urlsplit('rpc://myhost?someparam#somefragment')
        self.assertEqual(result.scheme, 'rpc')
        self.assertEqual(result.netloc, 'myhost')
        self.assertEqual(result.path, '')
        self.assertEqual(result.query, 'someparam')
        self.assertEqual(result.fragment, 'somefragment')

        result = netutils.urlsplit(
            'rpc://myhost/mypath?someparam#somefragment',
            allow_fragments=False)
        self.assertEqual(result.scheme, 'rpc')
        self.assertEqual(result.netloc, 'myhost')
        self.assertEqual(result.path, '/mypath')
        self.assertEqual(result.query, 'someparam#somefragment')
        self.assertEqual(result.fragment, '')

        result = netutils.urlsplit(
            'rpc://user:pass@myhost/mypath?someparam#somefragment',
            allow_fragments=False)
        self.assertEqual(result.scheme, 'rpc')
        self.assertEqual(result.netloc, 'user:pass@myhost')
        self.assertEqual(result.path, '/mypath')
        self.assertEqual(result.query, 'someparam#somefragment')
        self.assertEqual(result.fragment, '')

    def test_urlsplit_ipv6(self):
        ipv6_url = 'http://[::1]:443/v2.0/'
        result = netutils.urlsplit(ipv6_url)
        self.assertEqual(result.scheme, 'http')
        self.assertEqual(result.netloc, '[::1]:443')
        self.assertEqual(result.path, '/v2.0/')
        self.assertEqual(result.hostname, '::1')
        self.assertEqual(result.port, 443)

        ipv6_url = 'http://user:pass@[::1]/v2.0/'
        result = netutils.urlsplit(ipv6_url)
        self.assertEqual(result.scheme, 'http')
        self.assertEqual(result.netloc, 'user:pass@[::1]')
        self.assertEqual(result.path, '/v2.0/')
        self.assertEqual(result.hostname, '::1')
        self.assertIsNone(result.port)

        ipv6_url = 'https://[2001:db8:85a3::8a2e:370:7334]:1234/v2.0/xy?ab#12'
        result = netutils.urlsplit(ipv6_url)
        self.assertEqual(result.scheme, 'https')
        self.assertEqual(result.netloc, '[2001:db8:85a3::8a2e:370:7334]:1234')
        self.assertEqual(result.path, '/v2.0/xy')
        self.assertEqual(result.hostname, '2001:db8:85a3::8a2e:370:7334')
        self.assertEqual(result.port, 1234)
        self.assertEqual(result.query, 'ab')
        self.assertEqual(result.fragment, '12')

    def test_urlsplit_params(self):
        test_url = "http://localhost/?a=b&c=d"
        result = netutils.urlsplit(test_url)
        self.assertEqual({'a': 'b', 'c': 'd'}, result.params())
        self.assertEqual({'a': 'b', 'c': 'd'}, result.params(collapse=False))

        test_url = "http://localhost/?a=b&a=c&a=d"
        result = netutils.urlsplit(test_url)
        self.assertEqual({'a': 'd'}, result.params())
        self.assertEqual({'a': ['b', 'c', 'd']}, result.params(collapse=False))

        test_url = "http://localhost"
        result = netutils.urlsplit(test_url)
        self.assertEqual({}, result.params())

        test_url = "http://localhost?"
        result = netutils.urlsplit(test_url)
        self.assertEqual({}, result.params())

    def test_set_tcp_keepalive(self):
        mock_sock = mock.Mock()
        netutils.set_tcp_keepalive(mock_sock, True, 100, 10, 5)
        calls = [
            mock.call.setsockopt(socket.SOL_SOCKET,
                                 socket.SO_KEEPALIVE, True),
        ]
        if hasattr(socket, 'TCP_KEEPIDLE'):
            calls += [
                mock.call.setsockopt(socket.IPPROTO_TCP,
                                     socket.TCP_KEEPIDLE, 100)
            ]
        if hasattr(socket, 'TCP_KEEPINTVL'):
            calls += [
                mock.call.setsockopt(socket.IPPROTO_TCP,
                                     socket.TCP_KEEPINTVL, 10),
            ]
        if hasattr(socket, 'TCP_KEEPCNT'):
            calls += [
                mock.call.setsockopt(socket.IPPROTO_TCP,
                                     socket.TCP_KEEPCNT, 5)
            ]
        mock_sock.assert_has_calls(calls)

        mock_sock.reset_mock()
        netutils.set_tcp_keepalive(mock_sock, False)
        self.assertEqual(1, len(mock_sock.mock_calls))

    @mock.patch.object(netutils, 'LOG', autospec=True)
    def test_is_valid_ipv4(self, mock_log):
        self.assertTrue(netutils.is_valid_ipv4('42.42.42.42'))

        self.assertFalse(netutils.is_valid_ipv4('-1.11.11.11'))

        self.assertFalse(netutils.is_valid_ipv4(''))

        self.assertFalse(netutils.is_valid_ipv4('10'))
        self.assertFalse(netutils.is_valid_ipv4('10.10'))
        self.assertFalse(netutils.is_valid_ipv4('10.10.10'))
        self.assertTrue(netutils.is_valid_ipv4('10.10.10.10'))
        mock_log.warning.assert_not_called()
        mock_log.reset_mock()

        self.assertFalse(
            netutils.is_valid_ipv4('10', strict=True)
        )
        self.assertFalse(
            netutils.is_valid_ipv4('10.10', strict=True)
        )
        self.assertFalse(
            netutils.is_valid_ipv4('10.10.10', strict=True)
        )
        mock_log.warning.assert_not_called()
        mock_log.reset_mock()
        self.assertTrue(
            netutils.is_valid_ipv4('10', strict=False)
        )
        self.assertTrue(
            netutils.is_valid_ipv4('10.10', strict=False)
        )
        self.assertTrue(
            netutils.is_valid_ipv4('10.10.10', strict=False)
        )
        mock_log.warning.assert_not_called()
        mock_log.reset_mock()

    def test_is_valid_ipv6(self):
        self.assertTrue(netutils.is_valid_ipv6('::1'))

        self.assertTrue(netutils.is_valid_ipv6('fe80::1%eth0'))

        self.assertFalse(netutils.is_valid_ip('fe%80::1%eth0'))

        self.assertFalse(netutils.is_valid_ipv6(
            '1fff::a88:85a3::172.31.128.1'))

        self.assertFalse(netutils.is_valid_ipv6(''))

    def test_get_noscope_ipv6(self):
        self.assertEqual('2001:db8::ff00:42:8329',
                         netutils.get_noscope_ipv6('2001:db8::ff00:42:8329%1'))
        self.assertEqual('ff02::5678',
                         netutils.get_noscope_ipv6('ff02::5678%eth0'))
        self.assertEqual('fe80::1', netutils.get_noscope_ipv6('fe80::1%eth0'))
        self.assertEqual('::1', netutils.get_noscope_ipv6('::1%eth0'))
        self.assertEqual('::1', netutils.get_noscope_ipv6('::1'))
        self.assertRaises(ValueError, netutils.get_noscope_ipv6, '::132:::')

    def test_escape_ipv6(self):
        self.assertEqual('[1234::1234]', netutils.escape_ipv6('1234::1234'))
        self.assertEqual('127.0.0.1', netutils.escape_ipv6('127.0.0.1'))

    def test_is_valid_ip(self):
        self.assertTrue(netutils.is_valid_ip('127.0.0.1'))

        self.assertTrue(netutils.is_valid_ip('2001:db8::ff00:42:8329'))

        self.assertTrue(netutils.is_valid_ip('fe80::1%eth0'))

        self.assertFalse(netutils.is_valid_ip('256.0.0.0'))

        self.assertFalse(netutils.is_valid_ip('::1.2.3.'))

        self.assertFalse(netutils.is_valid_ip(''))

        self.assertFalse(netutils.is_valid_ip(None))

    def test_is_valid_mac(self):
        self.assertTrue(netutils.is_valid_mac("52:54:00:cf:2d:31"))
        self.assertFalse(netutils.is_valid_mac("127.0.0.1"))
        self.assertFalse(netutils.is_valid_mac("not:a:mac:address"))
        self.assertFalse(netutils.is_valid_mac("52-54-00-cf-2d-31"))
        self.assertFalse(netutils.is_valid_mac("aa bb cc dd ee ff"))
        self.assertTrue(netutils.is_valid_mac("AA:BB:CC:DD:EE:FF"))
        self.assertFalse(netutils.is_valid_mac("AA BB CC DD EE FF"))
        self.assertFalse(netutils.is_valid_mac("AA-BB-CC-DD-EE-FF"))

    def test_is_valid_cidr(self):
        self.assertTrue(netutils.is_valid_cidr('10.0.0.0/24'))
        self.assertTrue(netutils.is_valid_cidr('10.0.0.1/32'))
        self.assertTrue(netutils.is_valid_cidr('0.0.0.0/0'))
        self.assertTrue(netutils.is_valid_cidr('2600::/64'))
        self.assertTrue(netutils.is_valid_cidr(
                        '0000:0000:0000:0000:0000:0000:0000:0001/32'))

        self.assertFalse(netutils.is_valid_cidr('10.0.0.1'))
        self.assertFalse(netutils.is_valid_cidr('10.0.0.1/33'))
        self.assertFalse(netutils.is_valid_cidr(10))

    def test_is_valid_ipv6_cidr(self):
        self.assertTrue(netutils.is_valid_ipv6_cidr("2600::/64"))
        self.assertTrue(netutils.is_valid_ipv6_cidr(
            "abcd:ef01:2345:6789:abcd:ef01:192.168.254.254/48"))
        self.assertTrue(netutils.is_valid_ipv6_cidr(
            "0000:0000:0000:0000:0000:0000:0000:0001/32"))
        self.assertTrue(netutils.is_valid_ipv6_cidr(
            "0000:0000:0000:0000:0000:0000:0000:0001"))
        self.assertFalse(netutils.is_valid_ipv6_cidr("foo"))
        self.assertFalse(netutils.is_valid_ipv6_cidr("127.0.0.1"))

    def test_valid_port(self):
        valid_inputs = [0, '0', 1, '1', 2, '3', '5', 8, 13, 21,
                        '80', '3246', '65535']
        for input_str in valid_inputs:
            self.assertTrue(netutils.is_valid_port(input_str))

    def test_valid_port_fail(self):
        invalid_inputs = ['-32768', '65536', 528491, '528491',
                          '528.491', 'thirty-seven', None]
        for input_str in invalid_inputs:
            self.assertFalse(netutils.is_valid_port(input_str))

    def test_get_my_ipv4(self):
        mock_sock = mock.Mock()
        mock_sock.getsockname.return_value = ['1.2.3.4', '']
        sock_attrs = {
            'return_value.__enter__.return_value': mock_sock}
        with mock.patch('socket.socket', **sock_attrs):
            addr = netutils.get_my_ipv4()
        self.assertEqual(addr, '1.2.3.4')

    def test_get_my_ipv4_disabled(self):
        with (mock.patch('socket.socket', side_effect=socket.error()),
              mock.patch('builtins.open', side_effect=FileNotFoundError())):
            addr = netutils.get_my_ipv4()
        self.assertEqual(addr, '127.0.0.1')

    def test_get_my_ipv6(self):
        mock_sock = mock.Mock()
        mock_sock.getsockname.return_value = ['2001:db8::2', '', '', '']
        sock_attrs = {
            'return_value.__enter__.return_value': mock_sock}
        with mock.patch('socket.socket', **sock_attrs):
            addr = netutils.get_my_ipv6()
        self.assertEqual(addr, '2001:db8::2')

    def test_is_int_in_range(self):
        valid_inputs = [(1, -100, 100),
                        ('1', -100, 100),
                        (100, -100, 100),
                        ('100', -100, 100),
                        (-100, -100, 100),
                        ('-100', -100, 100)]
        for input_value in valid_inputs:
            self.assertTrue(netutils._is_int_in_range(*input_value))

    def test_is_int_not_in_range(self):
        invalid_inputs = [(None, 1, 100),
                          ('ten', 1, 100),
                          (-1, 0, 255),
                          ('None', 1, 100)]
        for input_value in invalid_inputs:
            self.assertFalse(netutils._is_int_in_range(*input_value))

    def test_valid_icmp_type(self):
        valid_inputs = [1, '1', 0, '0', 255, '255']
        for input_value in valid_inputs:
            self.assertTrue(netutils.is_valid_icmp_type(input_value))

    def test_invalid_icmp_type(self):
        invalid_inputs = [-1, '-1', 256, '256', None, 'None', 'five']
        for input_value in invalid_inputs:
            self.assertFalse(netutils.is_valid_icmp_type(input_value))

    def test_valid_icmp_code(self):
        valid_inputs = [1, '1', 0, '0', 255, '255', None]
        for input_value in valid_inputs:
            self.assertTrue(netutils.is_valid_icmp_code(input_value))

    def test_invalid_icmp_code(self):
        invalid_inputs = [-1, '-1', 256, '256', 'None', 'zero']
        for input_value in invalid_inputs:
            self.assertFalse(netutils.is_valid_icmp_code(input_value))

    @mock.patch('socket.socket')
    @mock.patch('oslo_utils.netutils._get_my_ipv4_address')
    def test_get_my_ipv4_socket_error(self, ip, mock_socket):
        mock_socket.side_effect = socket.error
        ip.return_value = '1.2.3.4'
        addr = netutils.get_my_ipv4()
        self.assertEqual(addr, '1.2.3.4')

    @mock.patch('socket.socket')
    @mock.patch('oslo_utils.netutils._get_my_ipv6_address')
    def test_get_my_ipv6_socket_error(self, ip, mock_socket):
        mock_socket.side_effect = socket.error
        ip.return_value = '2001:db8::2'
        addr = netutils.get_my_ipv6()
        self.assertEqual(addr, '2001:db8::2')

    @mock.patch('builtins.open')
    @mock.patch('psutil.net_if_addrs')
    def test_get_my_ipv4_address_with_default_route(
            self, mock_ifaddrs, mock_open):
        mock_open.return_value = io.StringIO(
            """Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	01cc12ac	0003	0	0	600	00000000	0	0	0
eth0	00cc12ac	00000000	0001	0	0	600	00FFFFFF	0	0	0
eth1	00cd12ac	00000000	0001	0	0	600	00FFFFFF	0	0	0""")  # noqa : E501

        addr = namedtuple('addr', ['family', 'address'])
        mock_ifaddrs.return_value = {
            'eth0': [
                addr(family=socket.AF_INET, address='172.18.204.2'),
                addr(family=socket.AF_INET6, address='2001:db8::2')
            ],
            'eth1': [
                addr(family=socket.AF_INET, address='172.18.205.2'),
                addr(family=socket.AF_INET6, address='2001:db8::1000::2')
            ]}
        self.assertEqual('172.18.204.2', netutils._get_my_ipv4_address())
        mock_open.assert_called_once_with('/proc/net/route')

    @mock.patch('builtins.open')
    @mock.patch('psutil.net_if_addrs')
    def test_get_my_ipv6_address_with_default_route(
            self, mock_ifaddrs, mock_open):
        mock_open.return_value = io.StringIO(
            """00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000000 00000000 00000000 08000000 eth0
20010db8000000000000000000000000 31 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 08000000 eth0
20010db8100000000000000000000000 31 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 08000000 eth1""")  # noqa: E501

        addr = namedtuple('addr', ['family', 'address'])
        mock_ifaddrs.return_value = {
            'eth0': [
                addr(family=socket.AF_INET, address='172.18.204.2'),
                addr(family=socket.AF_INET6, address='2001:db8::2')
            ],
            'eth1': [
                addr(family=socket.AF_INET, address='172.18.205.2'),
                addr(family=socket.AF_INET6, address='2001:db8::1000::2')
            ]}
        self.assertEqual('2001:db8::2', netutils._get_my_ipv6_address())
        mock_open.assert_called_once_with('/proc/net/ipv6_route')

    @mock.patch('builtins.open')
    @mock.patch('psutil.net_if_addrs')
    def test_get_my_ipv4_address_without_default_route(
            self, mock_ifaddrs, mock_open):
        mock_open.return_value = io.StringIO(
            """Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00cc12ac	00000000	0001	0	0	600	00FFFFFF	0	0	0
eth1	00cd12ac	00000000	0001	0	0	600	00FFFFFF	0	0	0""")  # noqa : E501

        self.assertEqual('127.0.0.1', netutils._get_my_ipv4_address())
        mock_open.assert_called_once_with('/proc/net/route')
        mock_ifaddrs.assert_not_called()

    @mock.patch('builtins.open')
    @mock.patch('psutil.net_if_addrs')
    def test_get_my_ipv6_address_without_default_route(
            self, mock_ifaddrs, mock_open):
        mock_open.return_value = io.StringIO(
            """20010db8000000000000000000000000 31 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 08000000 eth0
20010db8100000000000000000000000 31 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 08000000 eth1""")  # noqa: E501

        self.assertEqual('::1', netutils._get_my_ipv6_address())
        mock_open.assert_called_once_with('/proc/net/ipv6_route')
        mock_ifaddrs.assert_not_called()


class IPv6byEUI64TestCase(test_base.BaseTestCase):
    """Unit tests to generate IPv6 by EUI-64 operations."""

    def test_generate_IPv6_by_EUI64(self):
        addr = netutils.get_ipv6_addr_by_EUI64('2001:db8::',
                                               '00:16:3e:33:44:55')
        self.assertEqual('2001:db8::216:3eff:fe33:4455', addr.format())

    def test_generate_IPv6_with_IPv4_prefix(self):
        ipv4_prefix = '10.0.8'
        mac = '00:16:3e:33:44:55'
        self.assertRaises(ValueError, lambda:
                          netutils.get_ipv6_addr_by_EUI64(ipv4_prefix, mac))

    def test_generate_IPv6_with_bad_mac(self):
        bad_mac = '00:16:3e:33:44:5Z'
        prefix = '2001:db8::'
        self.assertRaises(ValueError, lambda:
                          netutils.get_ipv6_addr_by_EUI64(prefix, bad_mac))

    def test_generate_IPv6_with_bad_prefix(self):
        mac = '00:16:3e:33:44:55'
        bad_prefix = 'bb'
        self.assertRaises(ValueError, lambda:
                          netutils.get_ipv6_addr_by_EUI64(bad_prefix, mac))

    def test_generate_IPv6_with_error_prefix_type(self):
        mac = '00:16:3e:33:44:55'
        prefix = 123
        self.assertRaises(TypeError, lambda:
                          netutils.get_ipv6_addr_by_EUI64(prefix, mac))

    def test_generate_IPv6_with_empty_prefix(self):
        mac = '00:16:3e:33:44:55'
        prefix = ''
        self.assertRaises(ValueError, lambda:
                          netutils.get_ipv6_addr_by_EUI64(prefix, mac))


class MACbyIPv6TestCase(test_base.BaseTestCase):
    """Unit tests to extract MAC from IPv6."""

    def test_reverse_generate_IPv6_by_EUI64(self):
        self.assertEqual(
            netaddr.EUI('00:16:3e:33:44:55'),
            netutils.get_mac_addr_by_ipv6(
                netaddr.IPAddress('2001:db8::216:3eff:fe33:4455')),
        )

    def test_random_qemu_mac(self):
        self.assertEqual(
            netaddr.EUI('52:54:00:42:02:19'),
            netutils.get_mac_addr_by_ipv6(
                netaddr.IPAddress('fe80::5054:ff:fe42:219')),
        )

    def test_local(self):
        self.assertEqual(
            netaddr.EUI('02:00:00:00:00:00'),
            netutils.get_mac_addr_by_ipv6(
                netaddr.IPAddress('fe80::ff:fe00:0')),
        )

    def test_universal(self):
        self.assertEqual(
            netaddr.EUI('00:00:00:00:00:00'),
            netutils.get_mac_addr_by_ipv6(
                netaddr.IPAddress('fe80::200:ff:fe00:0')),
        )


@contextlib.contextmanager
def mock_file_content(content):
    # Allows StringIO to act like a context manager-enabled file.
    yield io.StringIO(content)


class TestIsIPv6Enabled(test_base.BaseTestCase):

    def setUp(self):
        super(TestIsIPv6Enabled, self).setUp()

        def reset_detection_flag():
            netutils._IS_IPV6_ENABLED = None
        reset_detection_flag()
        self.addCleanup(reset_detection_flag)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('builtins.open', return_value=mock_file_content('0'))
    def test_enabled(self, mock_open, exists):
        enabled = netutils.is_ipv6_enabled()
        self.assertTrue(enabled)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('builtins.open', return_value=mock_file_content('1'))
    def test_disabled(self, mock_open, exists):
        enabled = netutils.is_ipv6_enabled()
        self.assertFalse(enabled)

    @mock.patch('os.path.exists', return_value=False)
    @mock.patch('builtins.open',
                side_effect=AssertionError('should not read'))
    def test_disabled_non_exists(self, mock_open, exists):
        enabled = netutils.is_ipv6_enabled()
        self.assertFalse(enabled)

    @mock.patch('os.path.exists', return_value=True)
    def test_memoize_enabled(self, exists):
        # Reset the flag to appear that we haven't looked for it yet.
        netutils._IS_IPV6_ENABLED = None
        with mock.patch('builtins.open',
                        return_value=mock_file_content('0')) as mock_open:
            enabled = netutils.is_ipv6_enabled()
            self.assertTrue(mock_open.called)
            self.assertTrue(netutils._IS_IPV6_ENABLED)
            self.assertTrue(enabled)
        # The second call should not use open again
        with mock.patch('builtins.open',
                        side_effect=AssertionError('should not be called')):
            enabled = netutils.is_ipv6_enabled()
            self.assertTrue(enabled)

    @mock.patch('os.path.exists', return_value=True)
    def test_memoize_disabled(self, exists):
        # Reset the flag to appear that we haven't looked for it yet.
        netutils._IS_IPV6_ENABLED = None
        with mock.patch('builtins.open',
                        return_value=mock_file_content('1')):
            enabled = netutils.is_ipv6_enabled()
            self.assertFalse(enabled)
        # The second call should not use open again
        with mock.patch('builtins.open',
                        side_effect=AssertionError('should not be called')):
            enabled = netutils.is_ipv6_enabled()
            self.assertFalse(enabled)

    @mock.patch('os.path.exists', return_value=False)
    @mock.patch('builtins.open',
                side_effect=AssertionError('should not read'))
    def test_memoize_not_exists(self, mock_open, exists):
        # Reset the flag to appear that we haven't looked for it yet.
        netutils._IS_IPV6_ENABLED = None
        enabled = netutils.is_ipv6_enabled()
        self.assertFalse(enabled)
        enabled = netutils.is_ipv6_enabled()
        self.assertFalse(enabled)
