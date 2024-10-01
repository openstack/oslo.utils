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
