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

    _test_data = b"Openstack forever"
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

    def test_password_mksalt(self):
        self.assertRaises(ValueError, secretutils.crypt_mksalt, 'MD5')
        salt = secretutils.crypt_mksalt('SHA-256')
        self.assertEqual(3 + 16, len(salt))
        self.assertTrue(salt.startswith('$5$'))
        salt = secretutils.crypt_mksalt('SHA-512')
        self.assertEqual(3 + 16, len(salt))
        self.assertTrue(salt.startswith('$6$'))

    def test_password_crypt(self):
        self.assertEqual(
            '$5$mysalt$fcnMdhaFpUmeWtGOgVuImueZGL1v0Q1kUVbV2NbFOX4',
            secretutils.crypt_password('mytopsecret', '$5$mysalt$'))
        self.assertEqual(
            '$6$mysalt$jTEJ24XtvcWmav/sTQb1tYqmk1kBQD/sxcMIxEPUcie'
            'J8L9AuCTWxYlxGz.XtIQYWspWkUXQz9zPIFTSKubP6.',
            secretutils.crypt_password('mytopsecret', '$6$mysalt$'))
