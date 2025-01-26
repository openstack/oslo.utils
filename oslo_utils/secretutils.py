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

"""
Secret utilities.

.. versionadded:: 3.5
"""

import ctypes
import ctypes.util
import hashlib
import hmac
import secrets
import string as _string

import debtcollector.removals


@debtcollector.removals.remove(message='Use hmac.compare_digest instead',
                               category=DeprecationWarning)
def constant_time_compare(*args, **kwargs):
    return hmac.compare_digest(*args, **kwargs)


@debtcollector.removals.remove(message='Use hashlib.md5 instead',
                               category=DeprecationWarning)
def md5(string=b'', usedforsecurity=True):
    """Return an md5 hashlib object using usedforsecurity parameter

    For python distributions that support the usedforsecurity keyword
    parameter, this passes the parameter through as expected.
    See https://bugs.python.org/issue9216
    """
    return hashlib.md5(string, usedforsecurity=usedforsecurity)  # nosec


if ctypes.util.find_library("crypt"):
    _libcrypt = ctypes.CDLL(ctypes.util.find_library("crypt"), use_errno=True)
    _crypt = _libcrypt.crypt
    _crypt.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
    _crypt.restype = ctypes.c_char_p
else:
    _crypt = None


def crypt_mksalt(method):
    """Make salt to encrypt password string

    This is provided as a replacement of crypt.mksalt method because crypt
    module was removed in Python 3.13.

    .. versionadded:: 8.0
    """
    # NOTE(tkajinam): The mksalt method in crypto module used to support MD5
    # and DES. However these are considered unsafe so we do not support these
    # to engourage more secure methods.
    methods = {'SHA-512': '$6$', 'SHA-256': '$5$'}
    if method not in methods:
        raise ValueError('Unsupported method: %s' % method)

    salt_set = _string.ascii_letters + _string.digits + './'
    return ''.join(
        [methods[method]] +
        [secrets.choice(salt_set) for c in range(16)])


def crypt_password(key, salt):
    """Encrtpt password string and generate the value in /etc/shadow format

    This is provided as a replacement of crypt.crypt method because crypt
    module was removed in Python 3.13.

    .. versionadded:: 8.0
    """
    if _crypt is None:
        raise RuntimeError('libcrypt is not available')
    return _crypt(key.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')
