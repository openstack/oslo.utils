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

import debtcollector.removals


@debtcollector.removals.remove(message='Use hmac.compare_digest instead',
                               category=PendingDeprecationWarning)
def constant_time_compare(*args, **kwargs):
    return hmac.compare_digest(*args, **kwargs)


@debtcollector.removals.remove(message='Use hashlib.md5 instead',
                               category=PendingDeprecationWarning)
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


def crypt_password(key, salt):
    """Encrtpt password string and generate the value in /etc/shadow format

    This is provided as a replacement of crypt.crypt method because crypt
    module was removed in Python 3.13.

    .. versionadded:: 7.5
    """
    if _crypt is None:
        raise RuntimeError('libcrypt is not available')
    return _crypt(key.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')
