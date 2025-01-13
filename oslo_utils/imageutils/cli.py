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
import argparse
import logging
import os
import sys
import textwrap

from oslo_utils.imageutils import format_inspector
from oslo_utils.version import version_info


def main():
    """Run image security checks and give feedback.

    Runs the image format detector and related security checks against
    a provided image.

    Usage:
    python -m oslo_utils.imageutils -i /path/to/image [-v|--verbose]

    Default behavior is to communicate status via exit code:
      - Exit code of 0 indicates a safe image.
      - Exit code of 1 indicates an unsafe or missing image.

    If verbose mode is enabled, KEY=VALUE is output for several useful
    pieces of information about the image and imageutils:
      - SAFETY_CHECK_PASSED (bool)
      - VIRTUAL_SIZE (virtual disk size)
      - ACTUAL_SIZE (actual size of image)
      - IMAGE_FORMAT (format of image)
      - OSLO_UTILS_VERSION (version of oslo_utils currently in use)
      - FAILURE_REASONS (reasons for failure, if failed safety check)
    """
    logging.basicConfig(level=logging.CRITICAL)
    oslo_utils_version = str(version_info)
    parser = argparse.ArgumentParser(
        prog='oslo.utils.imageutils',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(textwrap.dedent('''\
        oslo.utils.imageutils image checking program.
          * Exit code of 0 indicates image passes safety check
          * Exit code of 1 indicates image fails safety check
        ''')),
        epilog=f"Testing using oslo.utils version {oslo_utils_version}")
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help=("Print detailed information about the image in "
                              "KEY=VALUE format. Defaults to no output."))
    parser.add_argument('-i', '--image',
                        action='store', required=True, metavar="IMG",
                        help="Path to an image you wish to inspect.")
    args = parser.parse_args()
    image = args.image
    verbose = args.verbose

    if not os.path.exists(image) or not os.path.isfile(image):
        print('Image path %s provided does not exist' % image, file=sys.stderr)
        sys.exit(1)

    inspector = format_inspector.detect_file_format(image)
    safe = True
    try:
        inspector.safety_check()
    except format_inspector.SafetyCheckFailed as e:
        safe = False
        failure_reasons = []
        for exc in e.failures.items():
            failure_reasons.append("{}: {}".format(exc[0], exc[1]))

    virtual_size = inspector.virtual_size
    actual_size = inspector.actual_size
    fmt = str(inspector)

    if verbose:
        print(f"SAFETY_CHECK_PASSED={safe}")
        print(f"VIRTUAL_SIZE={virtual_size}")
        print(f"ACTUAL_SIZE={actual_size}")
        print(f"IMAGE_FORMAT=\"{fmt}\"")
        print(f"OSLO_UTILS_VERSION=\"{oslo_utils_version}\"")
    if safe:
        sys.exit(0)

    if verbose:
        print('FAILURE_REASONS=\'%s\'' % ','.join(failure_reasons))

    sys.exit(1)
