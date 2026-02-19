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

"""LUKS v1 decryption support for the format inspector.

This module implements the cryptographic operations needed to decrypt
the first block of a LUKS v1 encrypted image, including:

- Key slot parsing
- PBKDF2 key derivation
- Anti-forensic (AF) split key merging
- AES-XTS and AES-CBC sector-by-sector decryption
- Master key recovery and verification

Note that the #noqa tags on the hash and algorithm things are because
we're constrained by what is allowed in the LUKS format and we are
not "using" these for security, we're just honoring what may be in
the file according to the spec.
"""

import hashlib
import logging
import struct
from typing import Any, TypedDict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import pbkdf2

LOG = logging.getLogger(__name__)

LUKS_SECTOR_SIZE = 512
KEY_SLOT_OFFSET = 208
KEY_SLOT_SIZE = 48
NUM_KEY_SLOTS = 8
LUKS_DIGESTSIZE = 20
LUKS_KEY_ENABLED = 0x00AC71F3
LUKS_KEY_DISABLED = 0x0000DEAD

# Map LUKS hash names to cryptography/hashlib equivalents
HASH_ALGO_MAP = {
    'sha1': (hashes.SHA1(), hashlib.sha1),  # noqa: S303
    'sha256': (hashes.SHA256(), hashlib.sha256),
    'sha512': (hashes.SHA512(), hashlib.sha512),
}


class LUKSHeader(TypedDict, total=False):
    magic: bytes
    version: int
    cipher_alg: bytes
    cipher_mode: bytes
    hash: bytes
    payload_offset: int
    key_bytes: int
    mk_digest: bytes
    mk_digest_salt: bytes
    mk_digest_iter: int


def parse_key_slot(
    header_data: bytes | bytearray, slot_num: int
) -> dict[str, Any]:
    """Parse a key slot from the header.

    Each key slot is 48 bytes:
    - 4 bytes: active (0x00AC71F3 = enabled)
    - 4 bytes: iterations
    - 32 bytes: salt
    - 4 bytes: key material offset (in sectors)
    - 4 bytes: stripes
    """
    if slot_num >= NUM_KEY_SLOTS:
        raise ValueError(f'Invalid key slot number: {slot_num}')

    offset = KEY_SLOT_OFFSET + (slot_num * KEY_SLOT_SIZE)
    slot_data = header_data[offset : offset + KEY_SLOT_SIZE]

    active, iterations, salt, key_offset, stripes = struct.unpack(
        '>II32sII', slot_data
    )

    return {
        'active': active == LUKS_KEY_ENABLED,
        'iterations': iterations,
        'salt': salt,
        'key_offset': key_offset,
        'stripes': stripes,
    }


def h1_hash(data: bytes, hash_fn: Any) -> bytes:
    """Apply LUKS H1 hash extension function.

    H1 partitions the input into blocks of digest_size and hashes each
    block with its block index prepended as a big-endian uint32.

    :param data: Input data to hash
    :param hash_fn: Hash function (e.g., hashlib.sha256)
    :returns: Hashed data of the same length as input
    """
    # Get digest size by creating a test hash
    digest_size = len(hash_fn(b'').digest())
    result = bytearray()

    # Process each block
    i = 0
    pos = 0
    while pos < len(data):
        # Get block (may be shorter than digest_size for last block)
        block_end = min(pos + digest_size, len(data))
        block = data[pos:block_end]

        # Hash with block index prepended (big-endian uint32)
        h = hash_fn()
        h.update(struct.pack('>I', i))
        h.update(block)
        block_hash = h.digest()

        # For last block, crop the hash to match block length
        if block_end == len(data) and len(block) < digest_size:
            result.extend(block_hash[: len(block)])
        else:
            result.extend(block_hash)

        pos = block_end
        i += 1

    return bytes(result)


def af_merge(
    split_key: bytes, key_length: int, stripes: int, hash_fn: Any
) -> bytes:
    """Merge an AFsplit key back to the original key.

    AFmerge reverses the AFsplit process:
    d[0] = 0
    d[k] = H(d[k-1] XOR s[k])  for k = 1..n-1
    D = d[n-1] XOR s[n]

    :param split_key: The split key material (key_length * stripes bytes)
    :param key_length: The length of the original key
    :param stripes: The number of stripes used in AFsplit
    :param hash_fn: The hash function to use for diffusion
    :returns: The merged/unsplit key
    """
    # Start with d[0] = 0
    d = bytearray(key_length)

    # Compute d[k] = H(d[k-1] XOR s[k]) for k = 1..n-1
    for i in range(stripes - 1):
        stripe_start = i * key_length
        stripe = split_key[stripe_start : stripe_start + key_length]

        # XOR d with stripe[i]
        xored = bytes(a ^ b for a, b in zip(d, stripe))

        # Apply H1 hash extension
        d = bytearray(h1_hash(xored, hash_fn))

    # Final step: D = d[n-1] XOR s[n]
    last_stripe_start = (stripes - 1) * key_length
    last_stripe = split_key[last_stripe_start : last_stripe_start + key_length]
    result = bytes(a ^ b for a, b in zip(d, last_stripe))

    return result


def _decrypt_aes_xts(
    encrypted_data: bytes | bytearray,
    key: bytes,
    start_sector: int,
) -> bytes:
    """Decrypt data using AES-XTS mode, sector by sector.

    For AES-256-XTS, we need a 512-bit (64-byte) key. LUKS doubles a
    32-byte key by using it as both halves.

    :param encrypted_data: The encrypted data
    :param key: The encryption key
    :param start_sector: The starting sector number for tweak calculation
    :returns: The decrypted data
    """
    if len(key) == 32:
        xts_key = key + key
    elif len(key) == 64:
        xts_key = key
    else:
        raise ValueError(f'Unexpected key length for XTS: {len(key)}')

    result = bytearray()

    for i in range(0, len(encrypted_data), LUKS_SECTOR_SIZE):
        sector_data = encrypted_data[i : i + LUKS_SECTOR_SIZE]
        sector_num = start_sector + (i // LUKS_SECTOR_SIZE)

        tweak = sector_num.to_bytes(16, byteorder='little')

        cipher = ciphers.Cipher(
            ciphers.algorithms.AES(xts_key),
            ciphers.modes.XTS(tweak),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        result.extend(
            decryptor.update(bytes(sector_data)) + decryptor.finalize()
        )

    return bytes(result)


def _decrypt_aes_cbc(
    encrypted_data: bytes | bytearray,
    key: bytes,
    cipher_mode: str,
    start_sector: int,
) -> bytes:
    """Decrypt data using AES-CBC mode, sector by sector.

    Supports both plain CBC (sector number as IV) and CBC-ESSIV
    (encrypted sector number as IV).

    :param encrypted_data: The encrypted data
    :param key: The encryption key
    :param cipher_mode: Full cipher mode string (e.g., 'cbc-essiv:sha256')
    :param start_sector: The starting sector number for IV calculation
    :returns: The decrypted data
    """
    result = bytearray()

    for i in range(0, len(encrypted_data), LUKS_SECTOR_SIZE):
        sector_data = encrypted_data[i : i + LUKS_SECTOR_SIZE]
        sector_num = start_sector + (i // LUKS_SECTOR_SIZE)

        if 'essiv:' in cipher_mode:
            essiv_hash = cipher_mode.split('essiv:')[1]
            hash_map = {
                'sha256': hashlib.sha256,
                'sha1': hashlib.sha1,
            }
            if essiv_hash not in hash_map:
                raise ValueError(f'Unsupported ESSIV hash: {essiv_hash}')

            hash_fn = hash_map[essiv_hash]
            iv_key = hash_fn(key).digest()[:16]
            iv_cipher = ciphers.Cipher(
                ciphers.algorithms.AES(iv_key),
                ciphers.modes.ECB(),  # noqa: S305
                backend=default_backend(),
            )
            iv_enc = iv_cipher.encryptor()
            iv = iv_enc.update(sector_num.to_bytes(16, byteorder='little'))
        else:
            iv = sector_num.to_bytes(16, byteorder='little')

        cipher = ciphers.Cipher(
            ciphers.algorithms.AES(key),
            ciphers.modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        result.extend(
            decryptor.update(bytes(sector_data)) + decryptor.finalize()
        )

    return bytes(result)


def decrypt_data(
    encrypted_data: bytes | bytearray,
    key: bytes,
    cipher_name: str,
    cipher_mode: str,
    start_sector: int = 0,
) -> bytes:
    """Decrypt data using the specified cipher and mode.

    :param encrypted_data: The encrypted data
    :param key: The encryption key
    :param cipher_name: Cipher name (e.g., 'aes')
    :param cipher_mode: Cipher mode (e.g., 'xts-plain64',
                                     'cbc-essiv:sha256')
    :param start_sector: The starting sector number for IV calculation
    :returns: The decrypted data
    """
    if cipher_name == 'aes' and cipher_mode.startswith('xts'):
        return _decrypt_aes_xts(encrypted_data, key, start_sector)
    elif cipher_name == 'aes' and cipher_mode.startswith('cbc'):
        return _decrypt_aes_cbc(encrypted_data, key, cipher_mode, start_sector)
    else:
        raise ValueError(
            f'Unsupported cipher/mode: {cipher_name}-{cipher_mode}'
        )


def check_iteration_limit(
    header: LUKSHeader,
    header_data: bytes | bytearray,
    iter_limit: int,
) -> bool:
    """Enforce that the iteration limit is not exceeded.

    :param header: Parsed LUKS header
    :param header_data: Raw header data (for parsing key slots)
    :param iter_limit: Maximum iterations allowed (0 = no limit)
    :returns: True if within limits, False otherwise
    """
    if iter_limit <= 0:
        return True

    if header['mk_digest_iter'] > iter_limit:
        LOG.debug(
            'Master key iteration limit exceeded: %i',
            header['mk_digest_iter'],
        )
        return False

    for slot_num in range(NUM_KEY_SLOTS):
        slot = parse_key_slot(header_data, slot_num)
        if not slot['active']:
            continue
        if slot['iterations'] > iter_limit:
            LOG.debug(
                'Key slot %i iteration limit exceeded: %i',
                slot_num,
                slot['iterations'],
            )
            return False

    return True


def recover_master_key(
    passphrase: bytes,
    header: LUKSHeader,
    header_data: bytes | bytearray,
    active_slot: dict[str, Any],
    encrypted_key_material: bytes | bytearray,
    iter_limit: int = 0,
) -> bytes | None:
    """Recover the master key from the passphrase.

    This implements the LUKS master key recovery algorithm:
    1. Derive a key from the passphrase using PBKDF2 with the slot's
       parameters
    2. Decrypt the key material using this derived key
    3. Run AFmerge to recover the master key candidate
    4. Verify the master key against the master key digest

    :param passphrase: The user's passphrase
    :param header: Parsed LUKS header
    :param header_data: Raw header data (for iteration limit checking)
    :param active_slot: Parsed active key slot
    :param encrypted_key_material: Encrypted key material bytes
    :param iter_limit: Maximum iterations allowed (0 = no limit)
    :returns: The master key if successful, None otherwise
    """
    hash_spec = header['hash'].rstrip(b'\x00').decode('ascii')
    key_bytes = header.get('key_bytes', 32)

    if hash_spec not in HASH_ALGO_MAP:
        LOG.error('Unsupported hash algorithm: %s', hash_spec)
        return None

    if not check_iteration_limit(header, header_data, iter_limit):
        LOG.error('Iteration limit exceeded, aborting master key recovery')
        return None

    hash_algo, hash_fn = HASH_ALGO_MAP[hash_spec]

    # Step 1: Derive the password key using PBKDF2
    LOG.debug('Deriving key from passphrase using PBKDF2')
    LOG.debug(
        '  Iterations: %d, salt: %s',
        active_slot['iterations'],
        active_slot['salt'].hex()[:32],
    )
    kdf = pbkdf2.PBKDF2HMAC(
        algorithm=hash_algo,
        length=key_bytes,
        salt=active_slot['salt'],
        iterations=active_slot['iterations'],
        backend=default_backend(),
    )
    pwd_derived = kdf.derive(passphrase)
    LOG.debug('  Derived key: %s', pwd_derived.hex()[:32])

    # Step 2: Decrypt the key material
    LOG.debug('Decrypting key material')
    LOG.debug(
        '  Encrypted key material size: %d bytes',
        len(encrypted_key_material),
    )
    cipher_name = header['cipher_alg'].rstrip(b'\x00').decode('ascii')
    cipher_mode = header['cipher_mode'].rstrip(b'\x00').decode('ascii')
    try:
        split_key = decrypt_data(
            encrypted_key_material,
            pwd_derived,
            cipher_name,
            cipher_mode,
            start_sector=0,
        )
    except Exception as e:
        LOG.error('Failed to decrypt key material: %s', e)
        return None

    LOG.debug('  Split key size: %d bytes', len(split_key))
    LOG.debug('  First 32 bytes: %s', split_key[:32].hex())

    # Step 3: AFmerge to recover the master key candidate
    LOG.debug('Running AFmerge to recover master key')
    LOG.debug('  key_bytes=%d, stripes=%d', key_bytes, active_slot['stripes'])
    master_key_candidate = af_merge(
        split_key, key_bytes, active_slot['stripes'], hash_fn
    )
    LOG.debug('  Master key candidate: %s', master_key_candidate.hex())

    # Step 4: Verify the master key
    LOG.debug('Verifying master key')
    LOG.debug('  MK digest salt: %s', header['mk_digest_salt'].hex()[:32])
    LOG.debug('  MK digest iter: %d', header['mk_digest_iter'])
    kdf_verify = pbkdf2.PBKDF2HMAC(
        algorithm=hash_algo,
        length=LUKS_DIGESTSIZE,
        salt=header['mk_digest_salt'],
        iterations=header['mk_digest_iter'],
        backend=default_backend(),
    )
    mk_digest = kdf_verify.derive(master_key_candidate)
    LOG.debug('  Computed digest: %s', mk_digest.hex())
    LOG.debug('  Expected digest: %s', header['mk_digest'].hex())

    if mk_digest == header['mk_digest']:
        LOG.debug('Master key verified successfully!')
        return master_key_candidate
    else:
        LOG.warning('Master key verification failed')
        return None
