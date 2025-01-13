# Copyright 2020 Red Hat, Inc
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

import io
import os
import struct
import subprocess
import tempfile
from unittest import mock

import ddt
from oslo_utils import units

from oslo_utils.imageutils import format_inspector
from oslo_utils.imageutils import QemuImgInfo
from oslotest import base as test_base


TEST_IMAGE_PREFIX = 'oslo-unittest-formatinspector-'


def get_size_format_from_qemu_img(filename):
    output = subprocess.check_output(
        'qemu-img info --output=json "%s"' % filename,
        shell=True)
    info = QemuImgInfo(output, format='json')
    return info.virtual_size, info.file_format


@ddt.ddt
class TestFormatInspectors(test_base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self._created_files = []

    def tearDown(self):
        super().tearDown()
        for fn in self._created_files:
            try:
                os.remove(fn)
            except Exception:
                pass

    def _create_iso(self, image_size, subformat='9660'):
        """Create an ISO file of the given size.

        :param image_size: The size of the image to create in bytes
        :param subformat: The subformat to use, if any
        """

        # these tests depend on mkisofs
        # being installed and in the path,
        # if it is not installed, skip
        try:
            subprocess.check_output('mkisofs --version', shell=True)
        except Exception:
            self.skipTest('mkisofs not installed')

        size = image_size // units.Mi
        base_cmd = "mkisofs"
        if subformat == 'udf':
            # depending on the distribution mkisofs may not support udf
            # and may be provided by genisoimage instead. As a result we
            # need to check if the command supports udf via help
            # instead of checking the installed version.
            # mkisofs --help outputs to stderr so we need to
            # redirect it to stdout to use grep.
            try:
                subprocess.check_output(
                    'mkisofs --help 2>&1 | grep udf', shell=True)
            except Exception:
                self.skipTest('mkisofs does not support udf format')
            base_cmd += " -udf"
        prefix = TEST_IMAGE_PREFIX
        prefix += '-%s-' % subformat
        fn = tempfile.mktemp(prefix=prefix, suffix='.iso')
        self._created_files.append(fn)
        subprocess.check_output(
            'dd if=/dev/zero of=%s bs=1M count=%i' % (fn, size),
            shell=True)
        # We need to use different file as input and output as the behavior
        # of mkisofs is version dependent if both the input and the output
        # are the same and can cause test failures
        out_fn = "%s.iso" % fn
        subprocess.check_output(
            '{} -V "TEST" -o {}  {}'.format(base_cmd, out_fn, fn),
            shell=True)
        self._created_files.append(out_fn)
        return out_fn

    def _create_gpt(self, image_size, subformat='gpt'):
        data = bytearray(b'\x00' * 512 * 10)
        # The last two bytes of the first sector is the little-endian signature
        # value 0xAA55
        data[510:512] = b'\x55\xAA'

        # This is one EFI Protective MBR partition in the first PTE slot,
        # which is 16 bytes starting at offset 446.
        data[446:446 + 16] = struct.pack('<BBBBBBBBII',
                                         0x00,  # boot
                                         0x00,  # start C
                                         0x02,  # start H
                                         0x00,  # start S
                                         0xEE,  # OS type
                                         0x00,  # end C
                                         0x00,  # end H
                                         0x00,  # end S
                                         0x01,  # start LBA
                                         0x00,  # size LBA
                                         )
        fn = tempfile.mktemp(prefix='{}-gpt-{}'.format(TEST_IMAGE_PREFIX,
                                                       subformat))
        with open(fn, 'wb') as f:
            f.write(data)
        self._created_files.append(fn)
        return fn

    def _create_luks(self, image_size, subformat):
        fn = tempfile.mktemp(suffix='.luks')
        cmd = ['qemu-img', 'create', '-f', 'luks',
               '--object', 'secret,id=sec0,data=secret-passphrase',
               '-o', 'key-secret=sec0', fn, '%i' % image_size]
        subprocess.check_output(' '.join(cmd), shell=True)
        return fn

    def _create_img(
            self, fmt, size, subformat=None, options=None,
            backing_file=None):
        """Create an image file of the given format and size.

        :param fmt: The format to create
        :param size: The size of the image to create in bytes
        :param subformat: The subformat to use, if any
        :param options: A dictionary of options to pass to the format
        :param backing_file: The backing file to use, if any
        """

        if fmt == 'iso':
            return self._create_iso(size, subformat)
        if fmt == 'gpt':
            return self._create_gpt(size, subformat)
        if fmt == 'luks':
            return self._create_luks(size, subformat)

        if fmt == 'vhd':
            # QEMU calls the vhd format vpc
            fmt = 'vpc'

        # these tests depend on qemu-img being installed and in the path,
        # if it is not installed, skip. we also need to ensure that the
        # format is supported by qemu-img, this can vary depending on the
        # distribution so we need to check if the format is supported via
        # the help output.
        try:
            subprocess.check_output(
                'qemu-img --help | grep %s' % fmt, shell=True)
        except Exception:
            self.skipTest(
                'qemu-img not installed or does not support %s format' % fmt)

        if options is None:
            options = {}
        opt = ''
        prefix = TEST_IMAGE_PREFIX

        if subformat:
            options['subformat'] = subformat
            prefix += subformat + '-'

        if options:
            opt += '-o ' + ','.join('{}={}'.format(k, v)
                                    for k, v in options.items())

        if backing_file is not None:
            opt += ' -b %s -F raw' % backing_file

        fn = tempfile.mktemp(prefix=prefix,
                             suffix='.%s' % fmt)
        self._created_files.append(fn)
        subprocess.check_output(
            'qemu-img create -f %s %s %s %i' % (fmt, opt, fn, size),
            shell=True)
        return fn

    def _create_allocated_vmdk(self, size_mb, subformat=None):
        # We need a "big" VMDK file to exercise some parts of the code of the
        # format_inspector. A way to create one is to first create an empty
        # file, and then to convert it with the -S 0 option.

        if subformat is None:
            # Matches qemu-img default, see `qemu-img convert -O vmdk -o help`
            subformat = 'monolithicSparse'

        prefix = TEST_IMAGE_PREFIX
        prefix += '-%s-' % subformat
        fn = tempfile.mktemp(prefix=prefix, suffix='.vmdk')
        self._created_files.append(fn)
        raw = tempfile.mktemp(prefix=prefix, suffix='.raw')
        self._created_files.append(raw)

        # Create a file with pseudo-random data, otherwise it will get
        # compressed in the streamOptimized format
        subprocess.check_output(
            'dd if=/dev/urandom of=%s bs=1M count=%i' % (raw, size_mb),
            shell=True)

        # Convert it to VMDK
        subprocess.check_output(
            'qemu-img convert -f raw -O vmdk -o subformat={} -S 0 {} {}'
            .format(subformat, raw, fn),
            shell=True)
        return fn

    def _test_format_at_block_size(self, format_name, img, block_size):
        wrapper = format_inspector.InspectWrapper(open(img, 'rb'),
                                                  format_name)
        current_block_size = block_size
        while True:
            chunk = wrapper.read(current_block_size)
            if not chunk:
                break
            # If we've already settled on a format, the block size no longer
            # really matters for correctness since we won't be capturing and
            # parsing anything else. Bump up the block size so we will eat
            # the rest of the file more efficiently. This matters for formats
            # that are non-sparse and for which the virtual_size calculation
            # relies on the actual size of the file (i.e. raw, gpt, luks, etc)
            try:
                if current_block_size == block_size and wrapper.format:
                    current_block_size = 64 * units.Ki
            except Exception:
                pass

        wrapper.close()
        self.assertIsNotNone(wrapper.format, 'Failed to detect format')
        return wrapper.format

    def _test_format_at_image_size(self, format_name, image_size,
                                   subformat=None, safety_check=False):
        """Test the format inspector for the given format at the
        given image size.

        :param format_name: The format to test
        :param image_size: The size of the image to create in bytes
        :param subformat: The subformat to use, if any
        """
        img = self._create_img(format_name, image_size, subformat=subformat)

        # Some formats have internal alignment restrictions making this not
        # always exactly like image_size, so get the real value for comparison
        virtual_size, _ = get_size_format_from_qemu_img(img)

        # Read the format in various sizes, some of which will read whole
        # sections in a single read, others will be completely unaligned, etc.
        block_sizes = [64 * units.Ki, 1 * units.Mi]
        # ISO images have a 32KB system area at the beginning of the image
        # as a result reading that in 17 or 512 byte blocks takes too long,
        # causing the test to fail. The 64KiB block size is enough to read
        # the system area and header in a single read. the 1MiB block size
        # adds very little time to the test so we include it.
        if format_name != 'iso':
            block_sizes.extend([17, 512])
        for block_size in block_sizes:
            fmt = self._test_format_at_block_size(format_name, img, block_size)
            self.assertTrue(fmt.format_match,
                            'Failed to match %s at size %i block %i' % (
                                format_name, image_size, block_size))
            self.assertEqual(virtual_size, fmt.virtual_size,
                             ('Failed to calculate size for %s at size %i '
                              'block %i') % (format_name, image_size,
                                             block_size))
            memory = sum(fmt.context_info.values())
            self.assertLess(memory, 512 * units.Ki,
                            'Format used more than 512KiB of memory: %s' % (
                                fmt.context_info))
            if safety_check:
                fmt.safety_check()
                # If the safety check is supposed to pass, we can also make
                # sure our detection works
                det = format_inspector.detect_file_format(img)
                self.assertEqual(det.__class__, fmt.__class__)

    def _test_format(self, format_name, subformat=None):
        # Try a few different image sizes, including some odd and very small
        # sizes
        for image_size in (512, 513, 2057, 7):
            self._test_format_at_image_size(format_name, image_size * units.Mi,
                                            subformat=subformat,
                                            safety_check=True)

    @ddt.data('qcow2', 'vhd', 'vhdx', 'vmdk', 'gpt', 'luks')
    def test_format(self, format):
        self._test_format(format)

    @ddt.unpack
    @ddt.data(('iso', 'iso9660'), ('iso', 'udf'), ('vmdk', 'streamOptimized'))
    def test_subformat(self, format, subformat):
        self._test_format(format, subformat=subformat)

    def _generate_bad_iso(self):
        # we want to emulate a malicious user who uploads a an
        # ISO file has a qcow2 header in the system area
        # of the ISO file
        # we will create a qcow2 image and an ISO file
        # and then copy the qcow2 header to the ISO file
        # e.g.
        #   mkisofs -o orig.iso /etc/resolv.conf
        #   qemu-img create orig.qcow2 -f qcow2 64M
        #   dd if=orig.qcow2 of=outcome bs=32K count=1
        #   dd if=orig.iso of=outcome bs=32K skip=1 seek=1

        qcow = self._create_img('qcow2', 10 * units.Mi)
        iso = self._create_iso(64 * units.Mi, subformat='9660')
        # first ensure the files are valid
        iso_fmt = self._test_format_at_block_size('iso', iso, 4 * units.Ki)
        self.assertTrue(iso_fmt.format_match)
        qcow_fmt = self._test_format_at_block_size('qcow2', qcow, 4 * units.Ki)
        self.assertTrue(qcow_fmt.format_match)
        # now copy the qcow2 header to an ISO file
        prefix = TEST_IMAGE_PREFIX
        prefix += '-bad-'
        fn = tempfile.mktemp(prefix=prefix, suffix='.iso')
        self._created_files.append(fn)
        subprocess.check_output(
            'dd if={} of={} bs=32K count=1'.format(qcow, fn),
            shell=True)
        subprocess.check_output(
            'dd if={} of={} bs=32K skip=1 seek=1'.format(iso, fn),
            shell=True)
        return qcow, iso, fn

    def test_bad_iso_qcow2(self):
        # Test that an iso with a qcow2 header in the system area will be
        # rejected because it matches more than one format (iso and qcow2).
        # This is an important case because qemu-img does not support iso,
        # and can be fooled into thinking one is a qcow2 by putting the header
        # for one in ISO9660's "system area", which is technically a valid
        # thing to do.
        _, _, fn = self._generate_bad_iso()

        self.assertRaisesRegex(format_inspector.ImageFormatError,
                               'Multiple formats detected',
                               self._test_format_at_block_size,
                               'iso', fn, 4 * units.Ki)

    def test_bad_iso_qcow2_multiple_matches(self):
        # Test that we can access multiple detected formats if we specifically
        # ask for them.
        _, _, fn = self._generate_bad_iso()
        with open(fn, 'rb') as f:
            wrapper = format_inspector.InspectWrapper(f)
            # Eat the whole file
            while wrapper.read(1024):
                pass

        # Make sure we fail the single-format test
        self.assertRaises(format_inspector.ImageFormatError,
                          getattr, wrapper, 'format')

        # Make sure the multiple detected formats are exposed
        self.assertEqual(['iso', 'qcow2'],
                         sorted(x.NAME for x in wrapper.formats))

    def test_from_file_reads_minimum(self):
        img = self._create_img('qcow2', 10 * units.Mi)
        file_size = os.stat(img).st_size
        fmt = format_inspector.QcowInspector.from_file(img)
        # We know everything we need from the first 512 bytes of a QCOW image,
        # so make sure that we did not read the whole thing when we inspect
        # a local file.
        self.assertLess(fmt.actual_size, file_size)

    def test_qed_always_unsafe(self):
        img = self._create_img('qed', 10 * units.Mi)
        fmt = format_inspector.get_inspector('qed').from_file(img)
        self.assertTrue(fmt.format_match)
        self.assertRaises(format_inspector.SafetyCheckFailed,
                          fmt.safety_check)

    def test_vmdk_non_sparse_unsafe(self):
        img = self._create_img('vmdk', 10 * units.Mi,
                               subformat='monolithicFlat')
        fmt = format_inspector.detect_file_format(img)
        self.assertEqual('vmdk', fmt.NAME)
        e = self.assertRaises(format_inspector.SafetyCheckFailed,
                              fmt.safety_check)
        self.assertIn('Unsupported subformat', str(e.failures['descriptor']))

    def _test_vmdk_bad_descriptor_offset(self, subformat=None):
        format_name = 'vmdk'
        image_size = 10 * units.Mi
        descriptorOffsetAddr = 0x1c
        BAD_ADDRESS = 0x400
        img = self._create_img(format_name, image_size, subformat=subformat)

        # Corrupt the header
        fd = open(img, 'r+b')
        fd.seek(descriptorOffsetAddr)
        fd.write(struct.pack('<Q', BAD_ADDRESS // 512))
        fd.close()

        # Read the format in various sizes, some of which will read whole
        # sections in a single read, others will be completely unaligned, etc.
        for block_size in (64 * units.Ki, 512, 17, 1 * units.Mi):
            self.assertRaisesRegex(format_inspector.ImageFormatError,
                                   'Wrong descriptor location',
                                   self._test_format_at_block_size,
                                   'vmdk', img, block_size)

    def test_vmdk_bad_descriptor_offset(self):
        self._test_vmdk_bad_descriptor_offset()

    def test_vmdk_bad_descriptor_offset_stream_optimized(self):
        self._test_vmdk_bad_descriptor_offset(subformat='streamOptimized')

    def _test_vmdk_bad_descriptor_mem_limit(self, subformat=None):
        format_name = 'vmdk'
        image_size = 5 * units.Mi
        virtual_size = 5 * units.Mi
        descriptorOffsetAddr = 0x1c
        descriptorSizeAddr = descriptorOffsetAddr + 8
        twoMBInSectors = (2 << 20) // 512
        # We need a big VMDK because otherwise we will not have enough data to
        # fill-up the CaptureRegion.
        img = self._create_allocated_vmdk(image_size // units.Mi,
                                          subformat=subformat)

        # Corrupt the end of descriptor address so it "ends" at 2MB
        fd = open(img, 'r+b')
        fd.seek(descriptorSizeAddr)
        fd.write(struct.pack('<Q', twoMBInSectors))
        fd.close()

        # Read the format in various sizes, some of which will read whole
        # sections in a single read, others will be completely unaligned, etc.
        for block_size in (64 * units.Ki, 512, 17, 1 * units.Mi):
            fmt = self._test_format_at_block_size(format_name, img, block_size)
            self.assertTrue(fmt.format_match,
                            'Failed to match %s at size %i block %i' % (
                                format_name, image_size, block_size))
            self.assertEqual(virtual_size, fmt.virtual_size,
                             ('Failed to calculate size for %s at size %i '
                              'block %i') % (format_name, image_size,
                                             block_size))
            memory = sum(fmt.context_info.values())
            self.assertLess(memory, 1.5 * units.Mi,
                            'Format used more than 1.5MiB of memory: %s' % (
                                fmt.context_info))

    def test_vmdk_bad_descriptor_mem_limit(self):
        self._test_vmdk_bad_descriptor_mem_limit()

    def test_vmdk_bad_descriptor_mem_limit_stream_optimized(self):
        self._test_vmdk_bad_descriptor_mem_limit(subformat='streamOptimized')

    def test_qcow2_safety_checks(self):
        # Create backing and data-file names (and initialize the backing file)
        backing_fn = tempfile.mktemp(prefix='backing')
        self._created_files.append(backing_fn)
        with open(backing_fn, 'w') as f:
            f.write('foobar')
        data_fn = tempfile.mktemp(prefix='data')
        self._created_files.append(data_fn)

        # A qcow with no backing or data file is safe
        fn = self._create_img('qcow2', 5 * units.Mi, None)
        inspector = format_inspector.QcowInspector.from_file(fn)
        inspector.safety_check()

        # A backing file makes it unsafe
        fn = self._create_img('qcow2', 5 * units.Mi, None,
                              backing_file=backing_fn)
        inspector = format_inspector.QcowInspector.from_file(fn)
        self.assertRaisesRegex(format_inspector.SafetyCheckFailed,
                               '.*backing_file.*',
                               inspector.safety_check)

        # A data-file makes it unsafe
        fn = self._create_img('qcow2', 5 * units.Mi,
                              options={'data_file': data_fn,
                                       'data_file_raw': 'on'})
        inspector = format_inspector.QcowInspector.from_file(fn)
        self.assertRaisesRegex(format_inspector.SafetyCheckFailed,
                               '.*data_file.*',
                               inspector.safety_check)

        # Trying to load a non-QCOW file is an error
        self.assertRaises(format_inspector.ImageFormatError,
                          format_inspector.QcowInspector.from_file,
                          backing_fn)

    def test_qcow2_feature_flag_checks(self):
        data = bytearray(512)
        data[0:4] = b'QFI\xFB'
        inspector = format_inspector.QcowInspector()
        inspector.region('header').data = data

        def set_version(ver):
            data[0x07] = ver
            inspector.region_complete('header')

        # All zeros, known version, no feature flags - all good
        set_version(3)
        inspector.check_unknown_features()

        # A feature flag set in the first byte (highest-order) is not
        # something we know about, so fail.
        data[0x48] = 0x01
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'Unknown QCOW2 features found',
                               inspector.check_unknown_features),

        # The first bit in the last byte (lowest-order) is known (the dirty
        # bit) so that should pass
        data[0x48] = 0x00
        data[0x4F] = 0x01
        inspector.check_unknown_features()

        # Currently (as of 2024), the high-order feature flag bit in the low-
        # order byte is not assigned, so make sure we reject it.
        data[0x4F] = 0x80
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'Unknown QCOW2 features found',
                               inspector.check_unknown_features),

        # Version 1 should be rejected outright
        set_version(1)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'Unsupported qcow2 version',
                               inspector.check_unknown_features)

        # Version 4 should be rejected outright
        set_version(4)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'Unsupported qcow2 version',
                               inspector.check_unknown_features)

        # Version 2 had no feature flagging, so with the above flags still
        # set, we should not process that data as feature flags and pass here.
        set_version(2)
        inspector.check_unknown_features()

    def test_qcow2_future_flags(self):

        class Qcow2Future(format_inspector.QcowInspector):
            """A hypothetical future where qcow2 has 12 extra features."""
            I_FEATURES_MAX_BIT = 12

        data = bytearray(512)
        data[0:4] = b'QFI\xFB'
        inspector = Qcow2Future()
        inspector.region('header').data = data
        data[0x07] = 3
        inspector.region_complete('header')

        # Bit 8 is allowed
        data[0x4F] = 0x80
        inspector.check_unknown_features()

        # Bit 9 is allowed
        data[0x4E] = 0x01
        inspector.check_unknown_features()

        # Bit 16 is not allowed
        data[0x4E] = 0x81
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'Unknown QCOW2 features found',
                               inspector.check_unknown_features)

    def test_vdi(self):
        self._test_format('vdi')

    def test_invalid_data(self):
        wrapper = format_inspector.InspectWrapper(open(__file__, 'rb'))
        while True:
            chunk = wrapper.read(32)
            if not chunk:
                break

        wrapper.close()
        # Make sure this was not detected as any other format
        self.assertEqual('raw', str(wrapper.format))

        # Make sure that all of the other inspectors do not match and did not
        # use too much memory
        for fmt in wrapper._inspectors:
            if str(fmt) == 'raw':
                continue
            self.assertFalse(fmt.format_match)
            memory = sum(fmt.context_info.values())
            self.assertLess(memory, 512 * units.Ki,
                            'Format used more than 512KiB of memory: %s' % (
                                fmt.context_info))

    def test_invalid_data_without_raw(self):
        wrapper = format_inspector.InspectWrapper(
            open(__file__, 'rb'),
            allowed_formats=['qcow2', 'vmdk'])
        while True:
            chunk = wrapper.read(32)
            if not chunk:
                break

        wrapper.close()
        # Make sure this was not detected as any other format
        self.assertRaises(format_inspector.ImageFormatError,
                          lambda: wrapper.format)

    def test_vmdk_invalid_type(self):
        fmt = format_inspector.VMDKInspector()
        with open(__file__, 'rb') as f:
            fmt.eat_chunk(f.read())

        fake_rgn = mock.MagicMock()
        fake_rgn.complete = True
        fake_rgn.data = b'foocreateType="someunknownformat"bar'

        with mock.patch.object(fmt, 'has_region', return_value=True):
            with mock.patch.object(fmt, 'region', return_value=fake_rgn):
                self.assertEqual(0, fmt.virtual_size)

    def test_vmdk_with_footer(self):
        img_fn = self._create_img('vmdk', 10 * units.Mi,
                                  subformat='streamOptimized')

        # Make the file signal that there is a footer, add a footer, but with
        # invalid data
        with open(img_fn, 'rb+') as f:
            # Write the "expect a footer" sentinel into the header
            f.seek(56)
            f.write(
                struct.pack('<Q', format_inspector.VMDKInspector.GD_AT_END))
            # Add room for the footer marker, footer, and EOS marker, but
            # filled with zeroes (which is invalid)
            f.seek(0, 2)
            f.write(b'\x00' * 512 * 3)
        fmt = format_inspector.VMDKInspector.from_file(img_fn)
        self.assertRaisesRegex(format_inspector.SafetyCheckFailed,
                               'footer',
                               fmt.safety_check)

        # Make the footer and footer/EOS markers legit
        header = bytearray(fmt.region('header').data)
        # This is gdOffset, which must not be GD_AT_END in the footer
        header[56:57] = b'\x00'
        with open(img_fn, 'rb+') as f:
            # This is the footer marker (type=3)
            f.seek(-512 * 3 + 12, 2)
            f.write(b'\x03\x00\x00\x00')
            # Second-to-last sector is the footer, which must be a copy of the
            # header but with gdOffset set to something other than the flag.
            f.seek(-512 * 2, 2)
            f.write(header)

        # With everything set to legit values, we should pass the check now
        fmt = format_inspector.VMDKInspector.from_file(img_fn)
        fmt.safety_check()

        # Make sure we properly detect this type of VMDK
        det = format_inspector.detect_file_format(img_fn)
        self.assertEqual(format_inspector.VMDKInspector, det.__class__)

    def test_vmdk_footer_checks(self):
        def make_header(sig=b'KDMV', ver=1, d_sec=1, d_off=0x200, gdo=None):
            return struct.pack('<4sIIQQQQIQQ', sig, ver, 0, 0, 0, d_sec, d_off,
                               0, 0,
                               gdo or format_inspector.VMDKInspector.GD_AT_END)

        def make_footer(fm_typ=3, fm_sz=0, fm_pad=b'\x00',
                        eos_typ=0, eos_sz=0, eos_pad=b'\x00',
                        **header):
            region = bytearray(b'\x00' * 512 * 3)
            region[512:1024] = make_header(**header)
            region[8] = fm_sz
            region[12] = fm_typ
            region[16:512] = fm_pad * 496

            region[1024 + 8] = eos_sz
            region[1024 + 12] = eos_typ
            region[1024 + 16:] = eos_pad * 496
            return region

        fmt = format_inspector.VMDKInspector()
        fmt.new_region('footer', format_inspector.EndCaptureRegion(512 * 3))
        fmt.region('header').data = make_header()

        # Signature must match header
        fmt.region('footer').data = make_footer(sig=b'leak')
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'signature', fmt.check_footer)

        # Version must match header
        fmt.region('footer').data = make_footer(ver=2)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'version', fmt.check_footer)

        # Descriptor cannot be longer
        fmt.region('footer').data = make_footer(d_sec=2)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'descriptor', fmt.check_footer)

        # Descriptor cannot be relocated
        fmt.region('footer').data = make_footer(d_off=0x300)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'descriptor', fmt.check_footer)

        # Footer must not have GD_AT_END implying another footer
        fmt.region('footer').data = make_footer()
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'another footer', fmt.check_footer)

        # Footer marker type must be correct
        fmt.region('footer').data = make_footer(gdo=123, fm_typ=7)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'marker', fmt.check_footer)

        # Footer marker must indicate size=0
        fmt.region('footer').data = make_footer(gdo=123, fm_sz=1)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'marker', fmt.check_footer)

        # Footer marker must be zero-padded
        fmt.region('footer').data = make_footer(gdo=123, fm_pad=b'\x01')
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'marker', fmt.check_footer)

        # EOS marker type must be correct
        fmt.region('footer').data = make_footer(gdo=123, eos_typ=7)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'marker', fmt.check_footer)

        # EOS marker must indicate size=0
        fmt.region('footer').data = make_footer(gdo=123, eos_sz=1)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'marker', fmt.check_footer)

        # EOS marker must be zero-padded
        fmt.region('footer').data = make_footer(gdo=123, eos_pad=b'\x01')
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'marker', fmt.check_footer)

        # Everything in place should pass
        fmt.region('footer').data = make_footer(gdo=123)
        fmt.check_footer()

    def test_vmdk_safety_checks(self):
        descriptor_lines = [
            '# a comment',
            'createType monolithicFlat',
            '',
            ' ',
            'someUnknownThing=foo',
            'ddb whatever',
            'rw 0 somefile.vmdk',
        ]

        def setup_check():
            fmt = format_inspector.VMDKInspector()
            fmt.region('header').data = b'KDMV' * 128
            data = ('\n'.join(descriptor_lines)).encode()
            data += b'\x00' * (512 - len(data))
            fmt.region('descriptor').data = data
            fmt.region_complete('descriptor')
            return fmt

        # This should fail because the createType header is broken
        fmt = setup_check()
        e = self.assertRaises(format_inspector.SafetyCheckFailed,
                              fmt.safety_check)
        self.assertIn('Unsupported subformat', str(e.failures['descriptor']))

        # This should fail because the createType is not safe
        descriptor_lines[1] = 'createType="monolithicFlat"'
        e = self.assertRaises(format_inspector.SafetyCheckFailed,
                              fmt.safety_check)
        self.assertIn('Unsupported subformat', str(e.failures['descriptor']))

        # Fix createType and make sure we pass now
        descriptor_lines[1] = 'createType="monolithicSparse"'
        fmt = setup_check()
        fmt.safety_check()

        # Add an extent in an invalid mode which we will not recognize and fail
        descriptor_lines.append('wronly 2048 somefile2.vmdk')
        fmt = setup_check()
        e = self.assertRaises(format_inspector.SafetyCheckFailed,
                              fmt.safety_check)
        self.assertIn('descriptor data', str(e.failures['descriptor']))

        # Add an extent with a valid mode but an invalid character
        descriptor_lines[-1] = 'rw 2048 /etc/hosts'
        fmt = setup_check()
        e = self.assertRaises(format_inspector.SafetyCheckFailed,
                              fmt.safety_check)
        self.assertIn('extent filenames', str(e.failures['descriptor']))

        # Make sure we fail if there are no extents
        descriptor_lines.pop()
        descriptor_lines.pop()
        fmt = setup_check()
        e = self.assertRaises(format_inspector.SafetyCheckFailed,
                              fmt.safety_check)
        self.assertIn('No extents found', str(e.failures['descriptor']))

    def test_vmdk_format_checks(self):
        # Invalid signature
        fmt = format_inspector.VMDKInspector()
        chunk = (b'\x00' * 512)
        self.assertRaisesRegex(format_inspector.ImageFormatError,
                               'Signature',
                               fmt.eat_chunk, chunk)

        # Good signature but unknown version
        fmt = format_inspector.VMDKInspector()
        chunk = b'KDMV\x00' + (b'\x00' * 512)
        self.assertRaisesRegex(format_inspector.ImageFormatError,
                               'Unsupported format version',
                               fmt.eat_chunk, chunk)

        # Good signature and version, no footer, invalid descriptor location
        fmt = format_inspector.VMDKInspector()
        chunk = bytearray(b'\x00' * 512)
        chunk[0:5] = b'KDMV\x01'
        self.assertRaisesRegex(format_inspector.ImageFormatError,
                               'Wrong descriptor location',
                               fmt.eat_chunk, chunk)

    def test_gpt_mbr_check(self):
        data = bytearray(b'\x00' * 512 * 2)
        data[510:512] = b'\x55\xAA'
        fmt = format_inspector.GPTInspector()

        def mkpte(n=0, boot=0, ostype=0xEE, starth=2, startlba=1):
            data[446 + n * 16:446 + n * 16 + 16] = struct.pack(
                '<BBBBBBBBII',
                boot,  # boot
                0x00,  # start C
                starth,  # start H
                0x00,  # start S
                ostype,  # OS type
                0x00,  # end C
                0x00,  # end H
                0x00,  # end S
                startlba,  # start LBA
                0x00,  # size LBA
                )
            fmt.region('mbr').data = data
            fmt.region_complete('mbr')

        # Make sure we pass with EFI partition and correct values
        mkpte()
        fmt.check_mbr_partitions()

        # Make sure we fail if the boot flag is not one of the valid values
        mkpte(boot=0xA)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'invalid boot flag',
                               fmt.check_mbr_partitions)

        # Make sure we fail if no partitions are defined. This is probably
        # not a safety problem, but may mean that we mis-identified the image.
        mkpte(ostype=0)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'no partitions defined',
                               fmt.check_mbr_partitions)

        # EFI Protective MBRs are not allowed to have any other partitions
        # defined other than the GPT-protecting one.
        mkpte()
        mkpte(n=1)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'invalid extra partitions',
                               fmt.check_mbr_partitions)

        # Make sure that we tolerate any start CHS value for non-EFI types,
        # but refuse outside the required values for EFI.
        mkpte(n=1, ostype=2)
        mkpte(ostype=0x8E, starth=1)
        fmt.check_mbr_partitions()
        mkpte(starth=1)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'invalid start CHS',
                               fmt.check_mbr_partitions)

        # Make sure that we tolerate any start LBA value for non-EFI types,
        # but refuse outside the required values for EFI.
        mkpte(ostype=0x8E, startlba=2)
        fmt.check_mbr_partitions()
        mkpte(startlba=2)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'invalid start LBA',
                               fmt.check_mbr_partitions)

    def test_unique_names(self):
        for key, inspector_cls in format_inspector.ALL_FORMATS.items():
            self.assertEqual(key, inspector_cls.NAME)


class TestFormatInspectorInfra(test_base.BaseTestCase):
    def _test_capture_region_bs(self, bs):
        data = b''.join(chr(x).encode() for x in range(ord('A'), ord('z')))

        regions = [
            format_inspector.CaptureRegion(3, 9),
            format_inspector.CaptureRegion(0, 256),
            format_inspector.CaptureRegion(32, 8),
            format_inspector.EndCaptureRegion(32),
            format_inspector.EndCaptureRegion(5),
        ]

        for region in regions:
            # None of them should be complete yet
            self.assertFalse(region.complete)

        pos = 0
        for i in range(0, len(data), bs):
            chunk = data[i:i + bs]
            pos += len(chunk)
            for region in regions:
                region.capture(chunk, pos)

        # The end regions should not be complete until we signal EOF
        self.assertFalse(regions[3].complete)
        self.assertFalse(regions[4].complete)

        for region in regions:
            try:
                region.finish()
            except AttributeError:
                pass

        self.assertEqual(data[3:12], regions[0].data)
        self.assertEqual(data[0:256], regions[1].data)
        self.assertEqual(data[32:40], regions[2].data)
        self.assertEqual(data[-32:], regions[3].data)
        self.assertEqual(data[-5:], regions[4].data)

        # The small regions should be complete
        self.assertTrue(regions[0].complete)
        self.assertTrue(regions[2].complete)

        # The end regions should be complete
        self.assertTrue(regions[3].complete)
        self.assertTrue(regions[4].complete)

        # This region extended past the available data, so not complete
        self.assertFalse(regions[1].complete)

    def test_capture_region(self):
        for block_size in (1, 3, 7, 13, 32, 64):
            self._test_capture_region_bs(block_size)

    def _get_wrapper(self, data):
        source = io.BytesIO(data)
        return format_inspector.InspectWrapper(source)

    def test_info_wrapper_file_like(self):
        data = b''.join(chr(x).encode() for x in range(ord('A'), ord('z')))
        wrapper = self._get_wrapper(data)

        read_data = b''
        while True:
            chunk = wrapper.read(8)
            if not chunk:
                break
            read_data += chunk

        self.assertEqual(data, read_data)

    def test_info_wrapper_iter_like(self):
        data = b''.join(chr(x).encode() for x in range(ord('A'), ord('z')))
        wrapper = self._get_wrapper(data)

        read_data = b''
        for chunk in wrapper:
            read_data += chunk

        self.assertEqual(data, read_data)

    @mock.patch.object(format_inspector.VMDKInspector, 'eat_chunk')
    def test_info_wrapper_file_like_eats_error(self, mock_eat):
        wrapper = self._get_wrapper(b'123456')
        mock_eat.side_effect = Exception('fail')

        data = b''
        while True:
            chunk = wrapper.read(3)
            if not chunk:
                break
            data += chunk

        # Make sure we got all the data despite the error
        self.assertEqual(b'123456', data)

        # Make sure we only called this once and never again after
        # the error was raised
        mock_eat.assert_called_once_with(b'123')

    @mock.patch.object(format_inspector.VMDKInspector, 'eat_chunk')
    @mock.patch.object(format_inspector.LOG, 'debug')
    def test_wrapper_iter_like_eats_error(self, mock_log, mock_eat,
                                          expected=None):
        wrapper = format_inspector.InspectWrapper(iter([b'123', b'456']),
                                                  expected_format=expected)
        mock_eat.side_effect = Exception('fail')

        data = b''
        for chunk in wrapper:
            data += chunk

        # Make sure we got all the data despite the error
        self.assertEqual(b'123456', data)

        # Make sure we only called this once and never again after
        # the error was raised
        mock_eat.assert_called_once_with(b'123')
        if expected:
            self.assertFalse(mock_log.called)
        else:
            self.assertTrue(mock_log.called)

    def test_wrapper_iter_like_eats_error_expected_quiet(self):
        # Test with an expected format, but not the one we're going to
        # intentionally fail to make sure that we do not log failures
        # for non-expected formats.
        self.test_wrapper_iter_like_eats_error(expected='vhd')

    def test_wrapper_aborts_early(self):
        # Run the InspectWrapper with non-qcow2 data, expecting qcow2, first
        # read past the header should raise the error and abort us early.
        data = io.BytesIO(b'\x00' * units.Mi)
        wrapper = format_inspector.InspectWrapper(data,
                                                  expected_format='qcow2')
        self.assertRaises(format_inspector.ImageFormatError,
                          wrapper.read, 2048)
        # We should only have read 2048 bytes from the 1MiB of source data if
        # we aborted early.
        self.assertEqual(2048, data.tell())

    def test_get_inspector(self):
        self.assertEqual(format_inspector.QcowInspector,
                         format_inspector.get_inspector('qcow2'))
        self.assertIsNone(format_inspector.get_inspector('foo'))

    def test_safety_check_records_result(self):
        def fake_check():
            raise format_inspector.SafetyViolation('myresult')

        check = format_inspector.SafetyCheck('foo', fake_check,
                                             description='a fake check')
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'myresult',
                               check)

    def test_safety_check_records_failure(self):
        # This check will fail with ValueError
        check = format_inspector.SafetyCheck('foo', lambda: int('a'),
                                             description='a fake check')
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'Unexpected error',
                               check)

    def test_safety_check_constants(self):
        null_check = format_inspector.SafetyCheck.null()
        self.assertIsInstance(null_check, format_inspector.SafetyCheck)
        self.assertIsNone(null_check())

        banned_check = format_inspector.SafetyCheck.banned()
        self.assertIsInstance(banned_check, format_inspector.SafetyCheck)
        self.assertRaisesRegex(format_inspector.SafetyViolation,
                               'not allowed',
                               banned_check)

    def test_safety_check_error_conditions(self):
        inspector = format_inspector.QcowInspector()
        self.assertRaisesRegex(format_inspector.ImageFormatError,
                               'Incomplete file.*',
                               inspector.safety_check)
        inspector.eat_chunk(b'\x00' * 512)
        self.assertRaisesRegex(format_inspector.ImageFormatError,
                               'content does not match',
                               inspector.safety_check)

        self.assertRaises(RuntimeError, inspector.add_safety_check, 'foo')

    def test_safety_checks_required(self):
        class BadSafetyCheck(format_inspector.FileInspector):
            def _initialize(self):
                # No safety checks!
                return

            @property
            def format_match(self):
                return True
        self.assertRaisesRegex(RuntimeError, 'at least one safety',
                               BadSafetyCheck)

    def test_finish_is_final(self):
        fmt = format_inspector.RawFileInspector()
        fmt.eat_chunk(b'\x00')
        fmt.finish()
        self.assertRaises(RuntimeError, fmt.eat_chunk, b'\x00')


class TestFormatInspectorsTargeted(test_base.BaseTestCase):
    def _make_vhd_meta(self, guid_raw, item_length):
        # Meta region header, padded to 32 bytes
        data = struct.pack('<8sHH', b'metadata', 0, 1)
        data += b'0' * 20

        # Metadata table entry, 16-byte GUID, 12-byte information,
        # padded to 32-bytes
        data += guid_raw
        data += struct.pack('<III', 256, item_length, 0)
        data += b'0' * 6

        return data

    def test_vhd_table_over_limit(self):
        ins = format_inspector.VHDXInspector()
        meta = format_inspector.CaptureRegion(0, 0)
        desired = b'012345678ABCDEF0'
        # This is a poorly-crafted image that specifies a larger table size
        # than is allowed
        meta.data = self._make_vhd_meta(desired, 33 * 2048)
        ins.new_region('metadata', meta)
        new_region = ins._find_meta_entry(ins._guid(desired))
        # Make sure we clamp to our limit of 32 * 2048
        self.assertEqual(
            format_inspector.VHDXInspector.VHDX_METADATA_TABLE_MAX_SIZE,
            new_region.length)

    def test_vhd_table_under_limit(self):
        ins = format_inspector.VHDXInspector()
        meta = format_inspector.CaptureRegion(0, 0)
        desired = b'012345678ABCDEF0'
        meta.data = self._make_vhd_meta(desired, 16 * 2048)
        ins.new_region('metadata', meta)
        new_region = ins._find_meta_entry(ins._guid(desired))
        # Table size was under the limit, make sure we get it back
        self.assertEqual(16 * 2048, new_region.length)
