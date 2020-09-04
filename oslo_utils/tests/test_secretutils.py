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

import hashlib
import hmac

from oslotest import base as test_base
import testscenarios

from oslo_utils import secretutils


class SecretUtilsTest(testscenarios.TestWithScenarios,
                      test_base.BaseTestCase):

    _gen_digest = lambda text: hmac.new(b'foo', text.encode('utf-8'),
                                        digestmod=hashlib.sha1).digest()
    scenarios = [
        ('binary', {'converter': _gen_digest}),
        ('unicode', {'converter': lambda text: text}),
    ]

    def test_constant_time_compare(self):
        # make sure it works as a compare, the "constant time" aspect
        # isn't appropriate to test in unittests

        # Make sure the unittests are applied to our function instead of
        # the built-in function, otherwise that is in vain.
        ctc = secretutils._constant_time_compare

        self.assertTrue(ctc(self.converter(u'abcd'),
                            self.converter(u'abcd')))
        self.assertTrue(ctc(self.converter(u''),
                            self.converter(u'')))
        self.assertTrue(ctc('abcd', 'abcd'))
        self.assertFalse(ctc(self.converter(u'abcd'),
                             self.converter(u'efgh')))
        self.assertFalse(ctc(self.converter(u'abc'),
                             self.converter(u'abcd')))
        self.assertFalse(ctc(self.converter(u'abc'),
                             self.converter(u'abc\x00')))
        self.assertFalse(ctc(self.converter(u''),
                             self.converter(u'abc')))
        self.assertTrue(ctc(self.converter(u'abcd1234'),
                            self.converter(u'abcd1234')))
        self.assertFalse(ctc(self.converter(u'abcd1234'),
                             self.converter(u'ABCD234')))
        self.assertFalse(ctc(self.converter(u'abcd1234'),
                             self.converter(u'a')))
        self.assertFalse(ctc(self.converter(u'abcd1234'),
                             self.converter(u'1234abcd')))
        self.assertFalse(ctc('abcd1234', '1234abcd'))

    _test_data = "Openstack forever".encode('utf-8')
    _md5_digest = hashlib.md5(_test_data).digest()

    def test_md5_with_data(self):
        digest = secretutils.md5(self._test_data).digest()
        self.assertEqual(digest, self._md5_digest)

        digest = secretutils.md5(self._test_data,
                                 usedforsecurity=True).digest()
        self.assertEqual(digest, self._md5_digest)

        digest = secretutils.md5(self._test_data,
                                 usedforsecurity=False).digest()
        self.assertEqual(digest, self._md5_digest)

    def test_md5_without_data(self):
        md5 = secretutils.md5()
        md5.update(self._test_data)
        digest = md5.digest()
        self.assertEqual(digest, self._md5_digest)

        md5 = secretutils.md5(usedforsecurity=True)
        md5.update(self._test_data)
        digest = md5.digest()
        self.assertEqual(digest, self._md5_digest)

        md5 = secretutils.md5(usedforsecurity=False)
        md5.update(self._test_data)
        digest = md5.digest()
        self.assertEqual(digest, self._md5_digest)

    def test_string_data_raises_type_error(self):
        self.assertRaises(TypeError, hashlib.md5, 'foo')
        self.assertRaises(TypeError, secretutils.md5, 'foo')
        self.assertRaises(
            TypeError, secretutils.md5, 'foo', usedforsecurity=True)
        self.assertRaises(
            TypeError, secretutils.md5, 'foo', usedforsecurity=False)

    def test_none_data_raises_type_error(self):
        self.assertRaises(TypeError, hashlib.md5, None)
        self.assertRaises(TypeError, secretutils.md5, None)
        self.assertRaises(
            TypeError, secretutils.md5, None, usedforsecurity=True)
        self.assertRaises(
            TypeError, secretutils.md5, None, usedforsecurity=False)
