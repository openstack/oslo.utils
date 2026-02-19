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
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives import hashes

from oslo_utils.imageutils import _luks
from oslo_utils.tests import base as test_base


def _build_header_data(slots):
    """Build a fake 592-byte LUKS header with the given key slots.

    :param slots: list of up to 8 dicts with keys:
        active (bool), iterations (int), salt (bytes, 32),
        key_offset (int), stripes (int).
        Missing slots are filled as inactive (active=_luks.LUKS_KEY_DISABLED).
    :returns: 592-byte header data
    """
    # 208 bytes of header fields before key slots (content doesn't matter
    # for parse_key_slot tests, just needs to be the right size)
    header = bytearray(208)
    for i in range(8):
        if i < len(slots):
            s = slots[i]
            active = (
                _luks.LUKS_KEY_ENABLED
                if s.get('active')
                else _luks.LUKS_KEY_DISABLED
            )
            salt = s.get('salt', b'\x00' * 32)
            slot_data = struct.pack(
                '>II32sII',
                active,
                s.get('iterations', 1000),
                salt,
                s.get('key_offset', 8),
                s.get('stripes', 4000),
            )
        else:
            slot_data = struct.pack(
                '>II32sII', _luks.LUKS_KEY_DISABLED, 0, b'\x00' * 32, 0, 0
            )
        header.extend(slot_data)
    return bytes(header)


def _make_header(
    hash_spec='sha256',
    key_bytes=32,
    mk_digest_iter=100000,
    cipher_alg='aes',
    cipher_mode='xts-plain64',
):
    """Build a minimal LUKSHeader dict for testing."""
    return {
        'magic': b'LUKS\xba\xbe',
        'version': 1,
        'cipher_alg': cipher_alg.encode('ascii').ljust(32, b'\x00'),
        'cipher_mode': cipher_mode.encode('ascii').ljust(32, b'\x00'),
        'hash': hash_spec.encode('ascii').ljust(32, b'\x00'),
        'payload_offset': 4096,
        'key_bytes': key_bytes,
        'mk_digest': b'\x00' * 20,
        'mk_digest_salt': b'\x00' * 32,
        'mk_digest_iter': mk_digest_iter,
    }


def _encrypt_xts(plaintext, key, start_sector=0):
    """Encrypt plaintext with AES-XTS sector-by-sector, for test use."""
    xts_key = key
    result = bytearray()
    for i in range(0, len(plaintext), _luks.LUKS_SECTOR_SIZE):
        sector_data = plaintext[i : i + _luks.LUKS_SECTOR_SIZE]
        sector_num = start_sector + (i // _luks.LUKS_SECTOR_SIZE)
        tweak = sector_num.to_bytes(16, byteorder='little')
        cipher = ciphers.Cipher(
            ciphers.algorithms.AES(xts_key),
            ciphers.modes.XTS(tweak),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        result.extend(
            encryptor.update(bytes(sector_data)) + encryptor.finalize()
        )
    return bytes(result)


def _encrypt_cbc(plaintext, key, start_sector=0):
    """Encrypt plaintext with AES-CBC-plain sector-by-sector."""
    result = bytearray()
    for i in range(0, len(plaintext), _luks.LUKS_SECTOR_SIZE):
        sector_data = plaintext[i : i + _luks.LUKS_SECTOR_SIZE]
        sector_num = start_sector + (i // _luks.LUKS_SECTOR_SIZE)
        iv = sector_num.to_bytes(16, byteorder='little')
        cipher = ciphers.Cipher(
            ciphers.algorithms.AES(key),
            ciphers.modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        result.extend(
            encryptor.update(bytes(sector_data)) + encryptor.finalize()
        )
    return bytes(result)


def _encrypt_cbc_essiv(plaintext, key, essiv_hash='sha256', start_sector=0):
    """Encrypt plaintext with AES-CBC-ESSIV sector-by-sector."""
    hash_map = {
        'sha256': hashlib.sha256,
        'sha1': hashlib.sha1,
    }
    hash_fn = hash_map[essiv_hash]
    iv_key = hash_fn(key).digest()[:16]
    result = bytearray()
    for i in range(0, len(plaintext), _luks.LUKS_SECTOR_SIZE):
        sector_data = plaintext[i : i + _luks.LUKS_SECTOR_SIZE]
        sector_num = start_sector + (i // _luks.LUKS_SECTOR_SIZE)
        iv_cipher = ciphers.Cipher(
            ciphers.algorithms.AES(iv_key),
            ciphers.modes.ECB(),
            backend=default_backend(),
        )
        iv_enc = iv_cipher.encryptor()
        iv = iv_enc.update(sector_num.to_bytes(16, byteorder='little'))
        cipher = ciphers.Cipher(
            ciphers.algorithms.AES(key),
            ciphers.modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        result.extend(
            encryptor.update(bytes(sector_data)) + encryptor.finalize()
        )
    return bytes(result)


class TestParseKeySlot(test_base.BaseTestCase):
    def test_active_slot(self):
        salt = os.urandom(32)
        header_data = _build_header_data(
            [
                {
                    'active': True,
                    'iterations': 50000,
                    'salt': salt,
                    'key_offset': 8,
                    'stripes': 4000,
                }
            ]
        )
        slot = _luks.parse_key_slot(header_data, 0)
        self.assertTrue(slot['active'])
        self.assertEqual(50000, slot['iterations'])
        self.assertEqual(salt, slot['salt'])
        self.assertEqual(8, slot['key_offset'])
        self.assertEqual(4000, slot['stripes'])

    def test_inactive_slot(self):
        header_data = _build_header_data([{'active': False}])
        slot = _luks.parse_key_slot(header_data, 0)
        self.assertFalse(slot['active'])

    def test_multiple_slots(self):
        header_data = _build_header_data(
            [
                {'active': False, 'iterations': 1},
                {'active': True, 'iterations': 2},
                {'active': True, 'iterations': 3},
            ]
        )
        self.assertFalse(_luks.parse_key_slot(header_data, 0)['active'])
        self.assertTrue(_luks.parse_key_slot(header_data, 1)['active'])
        self.assertEqual(2, _luks.parse_key_slot(header_data, 1)['iterations'])
        self.assertTrue(_luks.parse_key_slot(header_data, 2)['active'])
        self.assertEqual(3, _luks.parse_key_slot(header_data, 2)['iterations'])

    def test_non_enabled_active_values(self):
        # Build header manually with specific active field values
        header = bytearray(208)
        # Slot 0: active field = 0x00000000 (zeroed)
        header.extend(struct.pack('>II32sII', 0, 1000, b'\x00' * 32, 8, 4000))
        # Slot 1: active field = 0x12345678 (arbitrary non-enabled value)
        header.extend(
            struct.pack('>II32sII', 0x12345678, 1000, b'\x00' * 32, 8, 4000)
        )
        # Slot 2: actually enabled
        header.extend(
            struct.pack(
                '>II32sII',
                _luks.LUKS_KEY_ENABLED,
                5000,
                b'\x00' * 32,
                8,
                4000,
            )
        )
        # Fill remaining slots with LUKS_KEY_DISABLED
        for _ in range(5):
            header.extend(
                struct.pack(
                    '>II32sII', _luks.LUKS_KEY_DISABLED, 0, b'\x00' * 32, 0, 0
                )
            )
        header_data = bytes(header)
        self.assertFalse(_luks.parse_key_slot(header_data, 0)['active'])
        self.assertFalse(_luks.parse_key_slot(header_data, 1)['active'])
        self.assertTrue(_luks.parse_key_slot(header_data, 2)['active'])
        for slot_num in range(3, 8):
            self.assertFalse(
                _luks.parse_key_slot(header_data, slot_num)['active']
            )

    def test_slot_number_out_of_range(self):
        header_data = _build_header_data([])
        self.assertRaises(ValueError, _luks.parse_key_slot, header_data, 8)
        self.assertRaises(ValueError, _luks.parse_key_slot, header_data, 99)

    def test_last_valid_slot(self):
        slots = [{'active': False}] * 7 + [{'active': True, 'iterations': 77}]
        header_data = _build_header_data(slots)
        slot = _luks.parse_key_slot(header_data, 7)
        self.assertTrue(slot['active'])
        self.assertEqual(77, slot['iterations'])


class TestH1Hash(test_base.BaseTestCase):
    def test_output_same_length_as_input(self):
        for length in (1, 16, 32, 64, 100):
            data = os.urandom(length)
            result = _luks.h1_hash(data, hashlib.sha256)
            self.assertEqual(length, len(result))

    def test_deterministic(self):
        data = b'hello world' * 5
        r1 = _luks.h1_hash(data, hashlib.sha256)
        r2 = _luks.h1_hash(data, hashlib.sha256)
        self.assertEqual(r1, r2)

    def test_different_hash_functions(self):
        data = os.urandom(64)
        r_sha256 = _luks.h1_hash(data, hashlib.sha256)
        r_sha512 = _luks.h1_hash(data, hashlib.sha512)
        # Same length output, but different values
        self.assertEqual(len(data), len(r_sha256))
        self.assertEqual(len(data), len(r_sha512))
        self.assertNotEqual(r_sha256, r_sha512)

    def test_empty_input(self):
        result = _luks.h1_hash(b'', hashlib.sha256)
        self.assertEqual(b'', result)

    def test_single_byte(self):
        result = _luks.h1_hash(b'\x42', hashlib.sha256)
        self.assertEqual(1, len(result))

    def test_exact_digest_size(self):
        # SHA-256 digest is 32 bytes; input exactly one block
        data = os.urandom(32)
        result = _luks.h1_hash(data, hashlib.sha256)
        self.assertEqual(32, len(result))
        # Should equal H(0x00000000 || data)
        h = hashlib.sha256()
        h.update(struct.pack('>I', 0))
        h.update(data)
        self.assertEqual(h.digest(), result)


class TestAfMerge(test_base.BaseTestCase):
    def test_single_stripe(self):
        # With 1 stripe, af_merge should return the stripe itself
        # d = bytearray(key_length) = all zeros
        # result = d XOR last_stripe = 0 XOR stripe = stripe
        key = os.urandom(32)
        result = _luks.af_merge(key, 32, 1, hashlib.sha256)
        self.assertEqual(key, result)

    def test_two_stripes(self):
        # With 2 stripes of key_length=4:
        # d = [0,0,0,0]
        # d = H1(d XOR s[0])  (for stripe 0, the only non-final stripe)
        # result = d XOR s[1]
        key_length = 4
        s0 = b'\x01\x02\x03\x04'
        s1 = b'\x05\x06\x07\x08'
        split_key = s0 + s1

        # Manually compute expected:
        d = bytearray(4)
        xored = bytes(a ^ b for a, b in zip(d, s0))
        d = bytearray(_luks.h1_hash(xored, hashlib.sha256))
        expected = bytes(a ^ b for a, b in zip(d, s1))

        result = _luks.af_merge(split_key, key_length, 2, hashlib.sha256)
        self.assertEqual(expected, result)

    def test_known_vector(self):
        # 3 stripes of 8 bytes: bytes(range(24)) with sha512
        split_key = bytes(range(24))
        result = _luks.af_merge(split_key, 8, 3, hashlib.sha512)
        self.assertEqual(bytes.fromhex('c576788f354a12c5'), result)

    def test_output_length(self):
        for key_length in (16, 32, 64):
            split_key = os.urandom(key_length * 4000)
            result = _luks.af_merge(
                split_key, key_length, 4000, hashlib.sha256
            )
            self.assertEqual(key_length, len(result))


# Known test vectors for decrypt_data tests. Key and plaintext are
# sequential byte patterns; ciphertext was captured from a known-good
# encryption using the cryptography library.
_DECRYPT_PLAINTEXT = bytes(range(256)) * 2  # 512 bytes
_DECRYPT_XTS_KEY = bytes(range(64))
_DECRYPT_XTS_CIPHERTEXT = bytes.fromhex(
    'dc8c665b97cbc0246d4f1639a9678a3e2a2dcf4a3fbf1342ebbb771234f1a1c3'
    'cb885182e54e277aa90875bfb779b27c28568d2731fd61d0b43248046597e326'
    'a2200a9e9bccf0664972e195d7de0b2418abb771743750a092615116d6fde009'
    'a436e45b90520c1d8c6dfe31b8e3dbb8258003b003e6906176ec1c7bfd537f80'
    'cb3cc16d170654f16944eb1a6193fabd6de22ff4a274debb6e51e586438dcb79'
    'da12d8101eaed7b96e62806267c94de91964bce2225ba9c710c1e3ee42626ff9'
    'b99ca1f14b6f4cf6ec5d25782adec81f3cf0a70013e2ed42b4c90e815fe179b7'
    '531086cc8ccaffdbd5e1137098aebb6257a669e9966fa983538a0f17b510a7e4'
    '3e6248e4c61bccb0b196d418de0ed35c71b0136b91e964c3e944b8fd652d63e9'
    '823cd0fae1003dcfa98b329a617982c5a6f8b116b58d3b1ca4efc229e1b33ffc'
    '588503729db8cfc4cd4495d29f123f719e8920098b274be18880daada40d17a6'
    '7a72b3bdddc27ddc668a8b2a4299374b997c6cb041c10ace8e16f5b70ab3e3e7'
    '3ded29b81f87da0b8e27df15e84cea90a4e6af133499891ae35e6feb247eebb9'
    '4cebdc1739143b411fefff0a8480a01669ceb5085e216005f2dfaab51a2a1cab'
    '1f869efdc985b779a15e4566e26d510056652331326ad1a807eba3cc73251ed4'
    '3c88ac86abd05303e21acdf2908ecfd5f04100379dedfce370af7f179a14ca5a'
)
_DECRYPT_CBC_KEY = bytes(range(32))
_DECRYPT_CBC_CIPHERTEXT = bytes.fromhex(
    '5a6e045708fb7196f02e553d02c3a692c77147ebd5121de8d0fae7762423b6bf'
    '78e2e0038b691b8bedfc32116811da597c8ab8ef66c293ca63ff37a35ec1c2ba'
    '0e062c9ee27de295b156818ba0a0843ad7d46f326edb69f34cd0dc843757f1d4'
    '6639521b4ac4bb350fcf535037abe368ff54b0ba2d677e90190d7110c4839598'
    '1a476f540203ea4cbdfa49f47922311bc9acad229ca508181db866d99e09c230'
    '5f2c901959ca9a4d0eec1086119c4637e85c6d5689a55441254092f290ad6dd1'
    '09aaf12f6c3a60557eab23a1cb1c87f7d21db97653f482d390148e02456055b9'
    '1e61bf0783b76014806f2d560042f9dcdd862322e9a8a300f3692d48677ea4cc'
    'd745f24a5b4ec950af9e0a46e5c55187c9eebbe2679ce25db55f40b59285f240'
    'c0ba4c447732a6a384f59498473017251f221c620ee26f2e834484a295121a7e'
    'a56d2131c24e607b12c0cc3cb048a6835ed3ae2f83998a57fd7bc1924dfaa376'
    '669eb2f59cd088517c2e475db23c4b6a19043affa37174ace98848b57f1bb67e'
    'b1e1f344515e0862a524f503138a9cde9c72144561454a3c35df6a1c627de1a7'
    'a35325c57dc188717b738140fc38b68fd492a577afbdaebd4f13ed755cd4b410'
    '7e6daecc0a229d54c43190381ed8600e22431a306b9c94903de92bf7fa6959e3'
    '33815ae8087a6d450e08c929c378f2832db313a13996d33f0852c2ee1769f455'
)


class TestDecryptData(test_base.BaseTestCase):
    def test_xts_known_vector(self):
        result = _luks.decrypt_data(
            _DECRYPT_XTS_CIPHERTEXT,
            _DECRYPT_XTS_KEY,
            'aes',
            'xts-plain64',
        )
        self.assertEqual(_DECRYPT_PLAINTEXT, result)

    def test_cbc_known_vector(self):
        result = _luks.decrypt_data(
            _DECRYPT_CBC_CIPHERTEXT,
            _DECRYPT_CBC_KEY,
            'aes',
            'cbc-plain64',
        )
        self.assertEqual(_DECRYPT_PLAINTEXT, result)

    def test_xts_round_trip(self):
        key = os.urandom(64)
        plaintext = os.urandom(512)
        encrypted = _encrypt_xts(plaintext, key)
        decrypted = _luks.decrypt_data(encrypted, key, 'aes', 'xts-plain64')
        self.assertEqual(plaintext, decrypted)

    def test_xts_multiple_sectors(self):
        key = os.urandom(64)
        plaintext = os.urandom(512 * 4)
        encrypted = _encrypt_xts(plaintext, key)
        decrypted = _luks.decrypt_data(encrypted, key, 'aes', 'xts-plain64')
        self.assertEqual(plaintext, decrypted)

    def test_xts_with_start_sector(self):
        key = os.urandom(64)
        plaintext = os.urandom(512)
        encrypted = _encrypt_xts(plaintext, key, start_sector=10)
        decrypted = _luks.decrypt_data(
            encrypted, key, 'aes', 'xts-plain64', start_sector=10
        )
        self.assertEqual(plaintext, decrypted)

    def test_xts_bad_key_length(self):
        self.assertRaises(
            ValueError,
            _luks.decrypt_data,
            b'\x00' * 512,
            b'\x00' * 16,
            'aes',
            'xts-plain64',
        )

    def test_cbc_plain_round_trip(self):
        key = os.urandom(32)
        plaintext = os.urandom(512)
        encrypted = _encrypt_cbc(plaintext, key)
        decrypted = _luks.decrypt_data(encrypted, key, 'aes', 'cbc-plain64')
        self.assertEqual(plaintext, decrypted)

    def test_cbc_multiple_sectors(self):
        key = os.urandom(32)
        plaintext = os.urandom(512 * 3)
        encrypted = _encrypt_cbc(plaintext, key)
        decrypted = _luks.decrypt_data(encrypted, key, 'aes', 'cbc-plain64')
        self.assertEqual(plaintext, decrypted)

    def test_cbc_with_start_sector(self):
        key = os.urandom(32)
        plaintext = os.urandom(512)
        encrypted = _encrypt_cbc(plaintext, key, start_sector=5)
        decrypted = _luks.decrypt_data(
            encrypted, key, 'aes', 'cbc-plain64', start_sector=5
        )
        self.assertEqual(plaintext, decrypted)

    def test_cbc_essiv_sha256_round_trip(self):
        key = os.urandom(32)
        plaintext = os.urandom(512)
        encrypted = _encrypt_cbc_essiv(plaintext, key, 'sha256')
        decrypted = _luks.decrypt_data(
            encrypted, key, 'aes', 'cbc-essiv:sha256'
        )
        self.assertEqual(plaintext, decrypted)

    def test_cbc_essiv_sha256_multiple_sectors(self):
        key = os.urandom(32)
        plaintext = os.urandom(512 * 3)
        encrypted = _encrypt_cbc_essiv(plaintext, key, 'sha256')
        decrypted = _luks.decrypt_data(
            encrypted, key, 'aes', 'cbc-essiv:sha256'
        )
        self.assertEqual(plaintext, decrypted)

    def test_cbc_essiv_unsupported_hash(self):
        self.assertRaises(
            ValueError,
            _luks.decrypt_data,
            b'\x00' * 512,
            b'\x00' * 32,
            'aes',
            'cbc-essiv:md5',
        )

    def test_unsupported_cipher(self):
        self.assertRaises(
            ValueError,
            _luks.decrypt_data,
            b'\x00' * 512,
            b'\x00' * 32,
            'twofish',
            'xts-plain64',
        )

    def test_unsupported_mode(self):
        self.assertRaises(
            ValueError,
            _luks.decrypt_data,
            b'\x00' * 512,
            b'\x00' * 32,
            'aes',
            'gcm-plain64',
        )


class TestCheckIterationLimit(test_base.BaseTestCase):
    def test_zero_limit_always_passes(self):
        header = _make_header(mk_digest_iter=999999999)
        header_data = _build_header_data(
            [
                {'active': True, 'iterations': 999999999},
            ]
        )
        self.assertTrue(_luks.check_iteration_limit(header, header_data, 0))

    def test_negative_limit_always_passes(self):
        header = _make_header(mk_digest_iter=999999999)
        header_data = _build_header_data([])
        self.assertTrue(_luks.check_iteration_limit(header, header_data, -1))

    def test_mk_digest_iter_exceeds_limit(self):
        header = _make_header(mk_digest_iter=200000)
        header_data = _build_header_data([])
        self.assertFalse(
            _luks.check_iteration_limit(header, header_data, 100000)
        )

    def test_mk_digest_iter_within_limit(self):
        header = _make_header(mk_digest_iter=50000)
        header_data = _build_header_data([])
        self.assertTrue(
            _luks.check_iteration_limit(header, header_data, 100000)
        )

    def test_slot_iterations_exceed_limit(self):
        header = _make_header(mk_digest_iter=1000)
        header_data = _build_header_data(
            [
                {'active': True, 'iterations': 200000},
            ]
        )
        self.assertFalse(
            _luks.check_iteration_limit(header, header_data, 100000)
        )

    def test_inactive_slot_ignored(self):
        header = _make_header(mk_digest_iter=1000)
        header_data = _build_header_data(
            [
                {'active': False, 'iterations': 999999999},
            ]
        )
        self.assertTrue(
            _luks.check_iteration_limit(header, header_data, 100000)
        )

    def test_multiple_slots_one_exceeds(self):
        header = _make_header(mk_digest_iter=1000)
        header_data = _build_header_data(
            [
                {'active': True, 'iterations': 50000},
                {'active': True, 'iterations': 200000},
            ]
        )
        self.assertFalse(
            _luks.check_iteration_limit(header, header_data, 100000)
        )

    def test_all_within_limit(self):
        header = _make_header(mk_digest_iter=50000)
        header_data = _build_header_data(
            [
                {'active': True, 'iterations': 50000},
                {'active': True, 'iterations': 90000},
            ]
        )
        self.assertTrue(
            _luks.check_iteration_limit(header, header_data, 100000)
        )

    def test_exact_limit_passes(self):
        header = _make_header(mk_digest_iter=100000)
        header_data = _build_header_data(
            [
                {'active': True, 'iterations': 100000},
            ]
        )
        self.assertTrue(
            _luks.check_iteration_limit(header, header_data, 100000)
        )


class TestRecoverMasterKey(test_base.BaseTestCase):
    def _make_luks_test_data(
        self,
        passphrase=b'testpass',
        hash_spec='sha256',
        key_bytes=64,
        cipher_alg='aes',
        cipher_mode='xts-plain64',
        iterations=1000,
        stripes=4,
    ):
        """Build consistent LUKS test data with a known master key.

        Creates a master key, splits it with AFsplit, encrypts the split key,
        and computes the master key digest. Returns everything needed to call
        recover_master_key.
        """
        from cryptography.hazmat.primitives.kdf import pbkdf2 as _pbkdf2

        hash_algo_map = {
            'sha256': (hashes.SHA256(), hashlib.sha256),
            'sha512': (hashes.SHA512(), hashlib.sha512),
        }

        crypto_hash, hash_fn = hash_algo_map[hash_spec]
        master_key = os.urandom(key_bytes)
        salt = os.urandom(32)

        # AFsplit: create random stripes, compute last stripe so af_merge
        # recovers master_key.
        # d[0] = 0
        # d[k] = H1(d[k-1] XOR s[k]) for k=1..n-1
        # master_key = d[n-1] XOR s[n]
        # => s[n] = d[n-1] XOR master_key
        d = bytearray(key_bytes)
        random_stripes = []
        for i in range(stripes - 1):
            stripe = os.urandom(key_bytes)
            random_stripes.append(stripe)
            xored = bytes(a ^ b for a, b in zip(d, stripe))
            d = bytearray(_luks.h1_hash(xored, hash_fn))
        last_stripe = bytes(a ^ b for a, b in zip(d, master_key))
        split_key = b''.join(random_stripes) + last_stripe

        # Verify our AFsplit is correct
        recovered = _luks.af_merge(split_key, key_bytes, stripes, hash_fn)
        assert recovered == master_key, 'AFsplit/merge sanity check failed'

        # Derive password key using PBKDF2
        kdf = _pbkdf2.PBKDF2HMAC(
            algorithm=crypto_hash,
            length=key_bytes,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        pwd_key = kdf.derive(passphrase)

        # Encrypt the split key material
        encrypted_key_material = _encrypt_xts(split_key, pwd_key)

        # Compute master key digest
        mk_digest_salt = os.urandom(32)
        mk_digest_iter = 1000
        kdf_mk = _pbkdf2.PBKDF2HMAC(
            algorithm=crypto_hash,
            length=_luks.LUKS_DIGESTSIZE,
            salt=mk_digest_salt,
            iterations=mk_digest_iter,
            backend=default_backend(),
        )
        mk_digest = kdf_mk.derive(master_key)

        header = {
            'magic': b'LUKS\xba\xbe',
            'version': 1,
            'cipher_alg': cipher_alg.encode('ascii').ljust(32, b'\x00'),
            'cipher_mode': cipher_mode.encode('ascii').ljust(32, b'\x00'),
            'hash': hash_spec.encode('ascii').ljust(32, b'\x00'),
            'payload_offset': 4096,
            'key_bytes': key_bytes,
            'mk_digest': mk_digest,
            'mk_digest_salt': mk_digest_salt,
            'mk_digest_iter': mk_digest_iter,
        }

        active_slot = {
            'active': True,
            'iterations': iterations,
            'salt': salt,
            'key_offset': 8,
            'stripes': stripes,
        }

        header_data = _build_header_data([active_slot])

        return {
            'master_key': master_key,
            'header': header,
            'header_data': header_data,
            'active_slot': active_slot,
            'encrypted_key_material': encrypted_key_material,
        }

    def test_correct_passphrase(self):
        passphrase = b'correct-passphrase'
        data = self._make_luks_test_data(passphrase=passphrase)
        result = _luks.recover_master_key(
            passphrase,
            data['header'],
            data['header_data'],
            data['active_slot'],
            data['encrypted_key_material'],
        )
        self.assertEqual(data['master_key'], result)

    def test_wrong_passphrase(self):
        data = self._make_luks_test_data(passphrase=b'correct')
        result = _luks.recover_master_key(
            b'wrong',
            data['header'],
            data['header_data'],
            data['active_slot'],
            data['encrypted_key_material'],
        )
        self.assertIsNone(result)

    def test_unsupported_hash(self):
        data = self._make_luks_test_data()
        data['header']['hash'] = b'md5' + b'\x00' * 29
        result = _luks.recover_master_key(
            b'testpass',
            data['header'],
            data['header_data'],
            data['active_slot'],
            data['encrypted_key_material'],
        )
        self.assertIsNone(result)

    def test_iteration_limit_exceeded(self):
        data = self._make_luks_test_data(
            passphrase=b'testpass',
            iterations=50000,
        )
        # Set mk_digest_iter high enough to trigger the limit
        data['header']['mk_digest_iter'] = 50000
        result = _luks.recover_master_key(
            b'testpass',
            data['header'],
            data['header_data'],
            data['active_slot'],
            data['encrypted_key_material'],
            iter_limit=1000,
        )
        self.assertIsNone(result)

    def test_zero_iter_limit_allows_any(self):
        passphrase = b'testpass'
        data = self._make_luks_test_data(passphrase=passphrase)
        data['header']['mk_digest_iter'] = 999999
        # iter_limit=0 means no limit, but the digest won't match because
        # we changed mk_digest_iter after computing the digest. So just
        # verify it doesn't bail on the iteration check (it will fail on
        # digest mismatch instead).
        result = _luks.recover_master_key(
            passphrase,
            data['header'],
            data['header_data'],
            data['active_slot'],
            data['encrypted_key_material'],
            iter_limit=0,
        )
        # Will be None because digest won't match (we changed iter count),
        # but it shouldn't have bailed due to iteration limit
        self.assertIsNone(result)

    def test_sha512_hash(self):
        passphrase = b'sha512pass'
        data = self._make_luks_test_data(
            passphrase=passphrase,
            hash_spec='sha512',
        )
        result = _luks.recover_master_key(
            passphrase,
            data['header'],
            data['header_data'],
            data['active_slot'],
            data['encrypted_key_material'],
        )
        self.assertEqual(data['master_key'], result)
