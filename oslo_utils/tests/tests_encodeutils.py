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

from unittest import mock

from oslo_i18n import fixture as oslo_i18n_fixture
from oslotest import base as test_base

from oslo_utils import encodeutils


class EncodeUtilsTest(test_base.BaseTestCase):

    def test_safe_decode(self):
        safe_decode = encodeutils.safe_decode
        self.assertRaises(TypeError, safe_decode, True)
        self.assertEqual('ni\xf1o',
                         safe_decode(b"ni\xc3\xb1o",
                                     incoming="utf-8"))

        self.assertEqual("strange",
                         safe_decode(b'\x80strange',
                                     errors='ignore'))

        self.assertEqual('\xc0', safe_decode(b'\xc0',
                         incoming='iso-8859-1'))

        # Forcing incoming to ascii so it falls back to utf-8
        self.assertEqual('ni\xf1o',
                         safe_decode(b'ni\xc3\xb1o',
                                     incoming='ascii'))

        self.assertEqual('foo', safe_decode(b'foo'))

    def test_safe_encode_none_instead_of_text(self):
        self.assertRaises(TypeError, encodeutils.safe_encode, None)

    def test_safe_encode_bool_instead_of_text(self):
        self.assertRaises(TypeError, encodeutils.safe_encode, True)

    def test_safe_encode_int_instead_of_text(self):
        self.assertRaises(TypeError, encodeutils.safe_encode, 1)

    def test_safe_encode_list_instead_of_text(self):
        self.assertRaises(TypeError, encodeutils.safe_encode, [])

    def test_safe_encode_dict_instead_of_text(self):
        self.assertRaises(TypeError, encodeutils.safe_encode, {})

    def test_safe_encode_tuple_instead_of_text(self):
        self.assertRaises(TypeError, encodeutils.safe_encode, ('foo', 'bar', ))

    def test_safe_encode_force_incoming_utf8_to_ascii(self):
        # Forcing incoming to ascii so it falls back to utf-8
        self.assertEqual(
            b'ni\xc3\xb1o',
            encodeutils.safe_encode(b'ni\xc3\xb1o',
                                    incoming='ascii'),
        )

    def test_safe_encode_same_encoding_different_cases(self):
        with mock.patch.object(encodeutils, 'safe_decode', mock.Mock()):
            utf8 = encodeutils.safe_encode(
                'foo\xf1bar', encoding='utf-8')
            self.assertEqual(
                encodeutils.safe_encode(utf8, 'UTF-8', 'utf-8'),
                encodeutils.safe_encode(utf8, 'utf-8', 'UTF-8'),
            )
            self.assertEqual(
                encodeutils.safe_encode(utf8, 'UTF-8', 'utf-8'),
                encodeutils.safe_encode(utf8, 'utf-8', 'utf-8'),
            )
            encodeutils.safe_decode.assert_has_calls([])

    def test_safe_encode_different_encodings(self):
        text = 'foo\xc3\xb1bar'
        result = encodeutils.safe_encode(
            text=text, incoming='utf-8', encoding='iso-8859-1')
        self.assertNotEqual(text, result)
        self.assertNotEqual(b"foo\xf1bar", result)

    def test_to_utf8(self):
        self.assertEqual(encodeutils.to_utf8(b'a\xe9\xff'),        # bytes
                         b'a\xe9\xff')
        self.assertEqual(encodeutils.to_utf8('a\xe9\xff\u20ac'),  # Unicode
                         b'a\xc3\xa9\xc3\xbf\xe2\x82\xac')
        self.assertRaises(TypeError, encodeutils.to_utf8, 123)     # invalid

        # oslo.i18n Message objects should also be accepted for convenience.
        # It works because Message is a subclass of str. Use the
        # lazy translation to get a Message instance of oslo_i18n.
        msg = oslo_i18n_fixture.Translation().lazy("test")
        self.assertEqual(encodeutils.to_utf8(msg),
                         b'test')
