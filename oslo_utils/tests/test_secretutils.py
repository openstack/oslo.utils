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

from oslo_utils import secretutils
from oslo_utils.tests import base as test_base


class SecretUtilsTest(test_base.BaseTestCase):
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
            secretutils.crypt_password('mytopsecret', '$5$mysalt$'),
        )
        self.assertEqual(
            '$6$mysalt$jTEJ24XtvcWmav/sTQb1tYqmk1kBQD/sxcMIxEPUcie'
            'J8L9AuCTWxYlxGz.XtIQYWspWkUXQz9zPIFTSKubP6.',
            secretutils.crypt_password('mytopsecret', '$6$mysalt$'),
        )
