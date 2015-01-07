#!/usr/bin/env python
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

"""Performance tests for mask_password.
"""

from __future__ import print_function

import timeit

from oslo_utils import strutils

# A moderately sized input (~50K) string
# http://paste.openstack.org/raw/155864/
# infile = '155864.txt'

# Untruncated version of the above (~310K)
# http://dl.sileht.net/public/payload.json.gz
infile = 'large_json_payload.txt'

with open(infile, 'r') as f:
    input_str = f.read()
print('payload has %d bytes' % len(input_str))

for pattern in strutils._SANITIZE_PATTERNS_2['admin_pass']:
    print('\ntesting %s' % pattern.pattern)
    t = timeit.Timer(
        "re.sub(pattern, r'\g<1>***\g<2>', payload)",
        """
import re
payload = '''%s'''
pattern = re.compile(r'''%s''')
""" % (input_str, pattern.pattern))
    print(t.timeit(1))

t = timeit.Timer(
    "strutils.mask_password('''" + input_str + "''')",
    "from oslo_utils import strutils",
)
print(t.timeit(1))
