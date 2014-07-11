# -*- coding: utf-8 -*-

# Copyright 2014 Red Hat, Inc.
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

from oslotest import base as test_base
import six

from oslo.utils import encodeutils


class EncodeUtilsTest(test_base.BaseTestCase):

    def test_safe_decode(self):
        safe_decode = encodeutils.safe_decode
        self.assertRaises(TypeError, safe_decode, True)
        self.assertEqual(six.u('ni\xf1o'), safe_decode(six.b("ni\xc3\xb1o"),
                         incoming="utf-8"))
        if six.PY2:
            # In Python 3, bytes.decode() doesn't support anymore
            # bytes => bytes encodings like base64
            self.assertEqual(six.u("test"), safe_decode("dGVzdA==",
                             incoming='base64'))

        self.assertEqual(six.u("strange"), safe_decode(six.b('\x80strange'),
                         errors='ignore'))

        self.assertEqual(six.u('\xc0'), safe_decode(six.b('\xc0'),
                         incoming='iso-8859-1'))

        # Forcing incoming to ascii so it falls back to utf-8
        self.assertEqual(six.u('ni\xf1o'), safe_decode(six.b('ni\xc3\xb1o'),
                         incoming='ascii'))

        self.assertEqual(six.u('foo'), safe_decode(b'foo'))

    def test_safe_encode(self):
        safe_encode = encodeutils.safe_encode
        self.assertRaises(TypeError, safe_encode, True)
        self.assertEqual(six.b("ni\xc3\xb1o"), safe_encode(six.u('ni\xf1o'),
                                                           encoding="utf-8"))
        if six.PY2:
            # In Python 3, str.encode() doesn't support anymore
            # text => text encodings like base64
            self.assertEqual(six.b("dGVzdA==\n"),
                             safe_encode("test", encoding='base64'))
        self.assertEqual(six.b('ni\xf1o'), safe_encode(six.b("ni\xc3\xb1o"),
                                                       encoding="iso-8859-1",
                                                       incoming="utf-8"))

        # Forcing incoming to ascii so it falls back to utf-8
        self.assertEqual(six.b('ni\xc3\xb1o'),
                         safe_encode(six.b('ni\xc3\xb1o'), incoming='ascii'))
        self.assertEqual(six.b('foo'), safe_encode(six.u('foo')))
