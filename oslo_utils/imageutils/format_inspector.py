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

"""
This is a python implementation of virtual disk format inspection routines
gathered from various public specification documents, as well as qemu disk
driver code. It attempts to store and parse the minimum amount of data
required, and in a streaming-friendly manner to collect metadata about
complex-format images.
"""

import abc
import struct

import logging
from oslo_utils._i18n import _
from oslo_utils import units

LOG = logging.getLogger(__name__)


def _chunked_reader(fileobj, chunk_size=512):
    while True:
        chunk = fileobj.read(chunk_size)
        if not chunk:
            break
        yield chunk


class CaptureRegion:
    """Represents a region of a file we want to capture.

    A region of a file we want to capture requires a byte offset into
    the file and a length. This is expected to be used by a data
    processing loop, calling capture() with the most recently-read
    chunk. This class handles the task of grabbing the desired region
    of data across potentially multiple fractional and unaligned reads.

    :param offset: Byte offset into the file starting the region
    :param length: The length of the region
    :param min_length: Consider this region complete if it has captured at
                       least this much data. This should generally NOT be used
                       but may be required for certain formats with highly
                       variable data structures.
    """

    def __init__(self, offset, length, min_length=None):
        self.offset = offset
        self.length = length
        self.data = b''
        self.min_length = min_length

    @property
    def complete(self):
        """Returns True when we have captured the desired data."""
        if self.min_length is not None:
            return self.min_length <= len(self.data)
        else:
            return self.length == len(self.data)

    def capture(self, chunk, current_position):
        """Process a chunk of data.

        This should be called for each chunk in the read loop, at least
        until complete returns True.

        :param chunk: A chunk of bytes in the file
        :param current_position: The position of the file processed by the
                                 read loop so far. Note that this will be
                                 the position in the file *after* the chunk
                                 being presented.
        """
        read_start = current_position - len(chunk)
        if (read_start <= self.offset <= current_position or
                self.offset <= read_start <= (self.offset + self.length)):
            if read_start < self.offset:
                lead_gap = self.offset - read_start
            else:
                lead_gap = 0
            self.data += chunk[lead_gap:]
            self.data = self.data[:self.length]


class EndCaptureRegion(CaptureRegion):
    """Represents a region that captures the last N bytes of a stream.

    This can only capture the last N bytes of a stream and not an arbitrary
    region referenced from the end of the file since in most cases we do not
    know how much data we will read.

    :param offset: Byte offset from the end of the stream to capture (which
                   will also be the region length)
    """
    def __init__(self, offset):
        super().__init__(offset, offset)
        # We don't want to indicate completeness until we have the data we
        # want *and* have reached EOF
        self._complete = False

    def capture(self, chunk, current_position):
        self.data += chunk
        self.data = self.data[0 - self.length:]
        self.offset = current_position - len(self.data)

    @property
    def complete(self):
        return super().complete and self._complete

    def finish(self):
        """Indicate that the entire stream has been read."""
        self._complete = True


class SafetyCheck:
    """Represents a named safety check on an inspector"""

    def __init__(self, name, target_fn, description=None):
        """A safety check, it's meta info, and result.

        @name should be a short name of the check (ideally no spaces)
        @target_fn is the implementation we run (no args) which returns either
                   None if the check passes, or a string reason why it failed.
        @description is a optional longer-format human-readable string that
                     describes the check.
        """
        self.name = name
        self.target_fn = target_fn
        self.description = description

    def __call__(self):
        """Executes the target check function, records the result.

        Returns True if the check succeeded (i.e. no failure reason) or
        False if it did not.
        """
        try:
            self.target_fn()
        except SafetyViolation:
            raise
        except Exception as e:
            LOG.error('Failed to run safety check %s on %s inspector: %s',
                      self.name, self, e)
            raise SafetyViolation(_('Unexpected error'))

    @classmethod
    def null(cls):
        """The "null" safety check always returns True.

        This should only be used if there is no meaningful checks that can
        be done for a given format.
        """
        return cls('null', lambda: None,
                   _('This file format has no meaningful safety check'))

    @classmethod
    def banned(cls):
        """The "banned" safety check always returns False.

        This should be used for formats we want to identify but never allow,
        generally because they are unsupported by any of our users and/or
        we are unable to check for safety.
        """
        def fail():
            raise SafetyViolation(_('This file format is not allowed'))
        return cls('banned', fail, _('This file format is not allowed'))


class ImageFormatError(Exception):
    """An unrecoverable image format error that aborts the process."""
    pass


class SafetyViolation(Exception):
    """Indicates a failure of a single safety violation."""
    pass


class SafetyCheckFailed(Exception):
    """Indictes that one or more of a series of safety checks failed."""
    def __init__(self, failures):
        super().__init__(_('Safety checks failed: %s') % ','.join(
            failures.keys()))
        self.failures = failures


class FileInspector(abc.ABC):
    """A stream-based disk image inspector.

    This base class works on raw images and is subclassed for more
    complex types. It is to be presented with the file to be examined
    one chunk at a time, during read processing and will only store
    as much data as necessary to determine required attributes of
    the file.
    """

    # This should match what qemu-img thinks this format is
    NAME = ''

    def __init__(self, tracing=False):
        self._total_count = 0

        # NOTE(danms): The logging in here is extremely verbose for a reason,
        # but should never really be enabled at that level at runtime. To
        # retain all that work and assist in future debug, we have a separate
        # debug flag that can be passed from a manual tool to turn it on.
        self._tracing = tracing
        self._capture_regions = {}
        self._safety_checks = {}
        self._finished = False
        self._initialize()
        if not self._safety_checks:
            # Make sure we actively declare some safety check, even if it
            # is a no-op.
            raise RuntimeError(
                'All inspectors must define at least one safety check')

    def _trace(self, *args, **kwargs):
        if self._tracing:
            LOG.debug(*args, **kwargs)

    @abc.abstractmethod
    def _initialize(self):
        """Set up inspector before we start processing data.

        This should add the initial set of capture regions and safety checks.
        """

    def finish(self):
        """Indicate that the entire stream has been read.

        This should be called when the entire stream has been completely read,
        which will mark any EndCaptureRegion objects as complete.
        """
        self._finished = True
        for region in self._capture_regions.values():
            if isinstance(region, EndCaptureRegion):
                region.finish()

    def _capture(self, chunk, only=None):
        if self._finished:
            raise RuntimeError('Inspector has been marked finished, '
                               'no more data processing allowed')
        for name, region in self._capture_regions.items():
            if only and name not in only:
                continue
            if isinstance(region, EndCaptureRegion) or not region.complete:
                region.capture(chunk, self._total_count)

    def eat_chunk(self, chunk):
        """Call this to present chunks of the file to the inspector."""
        pre_regions = set(self._capture_regions.values())
        pre_complete = {region for region in self._capture_regions.values()
                        if region.complete}

        # Increment our position-in-file counter
        self._total_count += len(chunk)

        # Run through the regions we know of to see if they want this
        # data
        self._capture(chunk)

        # Let the format do some post-read processing of the stream
        self.post_process()

        # Check to see if the post-read processing added new regions
        # which may require the current chunk.
        new_regions = set(self._capture_regions.values()) - pre_regions
        if new_regions:
            self._capture(chunk, only=[self.region_name(r)
                                       for r in new_regions])

        post_complete = {region for region in self._capture_regions.values()
                         if region.complete}
        # Call the handler for any regions that are newly complete
        for region in post_complete - pre_complete:
            self.region_complete(self.region_name(region))

    def post_process(self):
        """Post-read hook to process what has been read so far.

        This will be called after each chunk is read and potentially captured
        by the defined regions. If any regions are defined by this call,
        those regions will be presented with the current chunk in case it
        is within one of the new regions.
        """
        pass

    def region(self, name):
        """Get a CaptureRegion by name."""
        return self._capture_regions[name]

    def region_name(self, region):
        """Return the region name for a region object."""
        for name in self._capture_regions:
            if self._capture_regions[name] is region:
                return name
        raise ValueError('No such region')

    def new_region(self, name, region):
        """Add a new CaptureRegion by name."""
        if self.has_region(name):
            # This is a bug, we tried to add the same region twice
            raise ImageFormatError('Inspector re-added region %s' % name)
        self._capture_regions[name] = region

    def has_region(self, name):
        """Returns True if named region has been defined."""
        return name in self._capture_regions

    def delete_region(self, name):
        """Remove a capture region by name.

        This will raise KeyError if the region does not exist.
        """
        del self._capture_regions[name]

    def region_complete(self, region_name):
        """Called when a region becomes complete.

        Subclasses may implement this if they need to do one-time processing
        of a region's data.
        """
        pass

    def add_safety_check(self, check):
        if not isinstance(check, SafetyCheck):
            raise RuntimeError(_('Unable to add safety check of type %s') % (
                type(check).__name__))
        if check.name in self._safety_checks:
            raise RuntimeError(_('Duplicate check of name %s') % check.name)
        self._safety_checks[check.name] = check

    @property
    @abc.abstractmethod
    def format_match(self):
        """Returns True if the file appears to be the expected format."""

    @property
    def virtual_size(self):
        """Returns the virtual size of the disk image, or zero if unknown."""
        return self._total_count

    @property
    def actual_size(self):
        """Returns the total size of the file, usually smaller than
        virtual_size. NOTE: this will only be accurate if the entire
        file is read and processed.
        """
        return self._total_count

    @property
    def complete(self):
        """Returns True if we have all the information needed."""
        return all(r.complete for r in self._capture_regions.values())

    def __str__(self):
        """The string name of this file format."""
        return self.NAME

    @property
    def context_info(self):
        """Return info on amount of data held in memory for auditing.

        This is a dict of region:sizeinbytes items that the inspector
        uses to examine the file.
        """
        return {name: len(region.data) for name, region in
                self._capture_regions.items()}

    @classmethod
    def from_file(cls, filename):
        """Read as much of a file as necessary to complete inspection.

        NOTE: Because we only read as much of the file as necessary, the
        actual_size property will not reflect the size of the file, but the
        amount of data we read before we satisfied the inspector.

        Raises ImageFormatError if we cannot parse the file.
        """
        inspector = cls()
        with open(filename, 'rb') as f:
            for chunk in _chunked_reader(f):
                inspector.eat_chunk(chunk)
                if inspector.complete:
                    # No need to eat any more data
                    break
        inspector.finish()
        if not inspector.complete or not inspector.format_match:
            raise ImageFormatError('File is not in requested format')
        return inspector

    def safety_check(self):
        """Perform all checks to determine if this file is safe.

        Returns if safe, raises otherwise. It may raise ImageFormatError
        if safety cannot be guaranteed because of parsing or other errors.
        It will raise SafetyCheckFailed if one or more checks fails.
        """
        if not self.complete:
            raise ImageFormatError(
                _('Incomplete file cannot be safety checked'))
        if not self.format_match:
            raise ImageFormatError(
                _('Unable to safety check format %s '
                  'because content does not match') % self)
        failures = {}
        for check in self._safety_checks.values():
            try:
                result = check()
                if result is not None:
                    raise RuntimeError('check returned result')
            except SafetyViolation as exc:
                exc.check = check
                failures[check.name] = exc
                LOG.warning('Safety check %s on %s failed because %s',
                            check.name, self, exc)
        if failures:
            raise SafetyCheckFailed(failures)


class RawFileInspector(FileInspector):
    NAME = 'raw'

    def _initialize(self):
        """Raw files have nothing to capture and no safety checks."""
        self.add_safety_check(SafetyCheck.null())

    @property
    def format_match(self):
        # By definition, raw files are unformatted and thus we always match
        return True


# The qcow2 format consists of a big-endian 72-byte header, of which
# only a small portion has information we care about:
#
# Dec   Hex   Name
#   0  0x00   Magic 4-bytes 'QFI\xfb'
#   4  0x04   Version (uint32_t, should always be 2 for modern files)
#  . . .
#   8  0x08   Backing file offset (uint64_t)
#  24  0x18   Size in bytes (unint64_t)
#  . . .
#  72  0x48   Incompatible features bitfield (6 bytes)
#
# https://gitlab.com/qemu-project/qemu/-/blob/master/docs/interop/qcow2.txt
class QcowInspector(FileInspector):
    """QEMU QCOW Format

    This should only require about 32 bytes of the beginning of the file
    to determine the virtual size, and 104 bytes to perform the safety check.

    This recognizes the (very) old v1 format but will raise a SafetyViolation
    for it, as it should definitely not be in production use at this point.
    """
    NAME = 'qcow2'
    BF_OFFSET = 0x08
    BF_OFFSET_LEN = 8
    I_FEATURES = 0x48
    I_FEATURES_LEN = 8
    I_FEATURES_DATAFILE_BIT = 3
    I_FEATURES_MAX_BIT = 4

    def _initialize(self):
        self.qemu_header_info = {}
        self.new_region('header', CaptureRegion(0, 512))
        self.add_safety_check(
            SafetyCheck('backing_file', self.check_backing_file))
        self.add_safety_check(
            SafetyCheck('data_file', self.check_data_file))
        self.add_safety_check(
            SafetyCheck('unknown_features', self.check_unknown_features))

    def region_complete(self, region):
        self.qemu_header_info = dict(zip(
            ('magic', 'version', 'bf_offset', 'bf_sz', 'cluster_bits', 'size'),
            struct.unpack('>4sIQIIQ', self.region('header').data[:32])))
        if not self.format_match:
            self.qemu_header_info = {}

    @property
    def virtual_size(self):
        return self.qemu_header_info.get('size', 0)

    @property
    def format_match(self):
        if not self.region('header').complete:
            return False
        return self.qemu_header_info.get('magic') == b'QFI\xFB'

    def check_backing_file(self):
        bf_offset_bytes = self.region('header').data[
            self.BF_OFFSET:self.BF_OFFSET + self.BF_OFFSET_LEN]
        # nonzero means "has a backing file"
        bf_offset, = struct.unpack('>Q', bf_offset_bytes)
        if bf_offset != 0:
            raise SafetyViolation('Image has a backing file')

    def check_unknown_features(self):
        ver = self.qemu_header_info.get('version')
        if ver == 2:
            # Version 2 did not have the feature flag array, so no need to
            # check it here.
            return
        elif ver != 3:
            raise SafetyViolation('Unsupported qcow2 version')

        i_features = self.region('header').data[
            self.I_FEATURES:self.I_FEATURES + self.I_FEATURES_LEN]

        # This is the maximum byte number we should expect any bits to be set
        max_byte = self.I_FEATURES_MAX_BIT // 8

        # The flag bytes are in big-endian ordering, so if we process
        # them in index-order, they're reversed
        for i, byte_num in enumerate(reversed(range(self.I_FEATURES_LEN))):
            if byte_num == max_byte:
                # If we're in the max-allowed byte, allow any bits less than
                # the maximum-known feature flag bit to be set
                allow_mask = ((1 << (self.I_FEATURES_MAX_BIT % 8)) - 1)
            elif byte_num > max_byte:
                # If we're above the byte with the maximum known feature flag
                # bit, then we expect all zeroes
                allow_mask = 0x0
            else:
                # Any earlier-than-the-maximum byte can have any of the flag
                # bits set
                allow_mask = 0xFF

            if i_features[i] & ~allow_mask:
                LOG.warning('Found unknown feature bit in byte %i: %s/%s',
                            byte_num, bin(i_features[byte_num] & ~allow_mask),
                            bin(allow_mask))
                raise SafetyViolation('Unknown QCOW2 features found')

    def check_data_file(self):
        i_features = self.region('header').data[
            self.I_FEATURES:self.I_FEATURES + self.I_FEATURES_LEN]

        # First byte of bitfield, which is i_features[7]
        byte = self.I_FEATURES_LEN - 1 - self.I_FEATURES_DATAFILE_BIT // 8
        # Third bit of bitfield, which is 0x04
        bit = 1 << (self.I_FEATURES_DATAFILE_BIT - 1 % 8)
        if bool(i_features[byte] & bit):
            raise SafetyViolation('Image has data_file set')


class QEDInspector(FileInspector):
    NAME = 'qed'

    def _initialize(self):
        self.new_region('header', CaptureRegion(0, 512))
        # QED format is not supported by anyone, but we want to detect it
        # and mark it as just always unsafe.
        self.add_safety_check(SafetyCheck.banned())

    @property
    def format_match(self):
        if not self.region('header').complete:
            return False
        return self.region('header').data.startswith(b'QED\x00')


# The VHD (or VPC as QEMU calls it) format consists of a big-endian
# 512-byte "footer" at the beginning of the file with various
# information, most of which does not matter to us:
#
# Dec   Hex   Name
#   0  0x00   Magic string (8-bytes, always 'conectix')
#  40  0x28   Disk size (uint64_t)
#
# https://github.com/qemu/qemu/blob/master/block/vpc.c
class VHDInspector(FileInspector):
    """Connectix/MS VPC VHD Format

    This should only require about 512 bytes of the beginning of the file
    to determine the virtual size.
    """
    NAME = 'vhd'

    def _initialize(self):
        self.new_region('header', CaptureRegion(0, 512))
        self.add_safety_check(SafetyCheck.null())

    @property
    def format_match(self):
        return self.region('header').data.startswith(b'conectix')

    @property
    def virtual_size(self):
        if not self.region('header').complete:
            return 0

        if not self.format_match:
            return 0

        return struct.unpack('>Q', self.region('header').data[40:48])[0]


# The VHDX format consists of a complex dynamic little-endian
# structure with multiple regions of metadata and data, linked by
# offsets with in the file (and within regions), identified by MSFT
# GUID strings. The header is a 320KiB structure, only a few pieces of
# which we actually need to capture and interpret:
#
#     Dec    Hex  Name
#      0 0x00000  Identity (Technically 9-bytes, padded to 64KiB, the first
#                 8 bytes of which are 'vhdxfile')
# 196608 0x30000  The Region table (64KiB of a 32-byte header, followed
#                 by up to 2047 36-byte region table entry structures)
#
# The region table header includes two items we need to read and parse,
# which are:
#
# 196608 0x30000  4-byte signature ('regi')
# 196616 0x30008  Entry count (uint32-t)
#
# The region table entries follow the region table header immediately
# and are identified by a 16-byte GUID, and provide an offset of the
# start of that region. We care about the "metadata region", identified
# by the METAREGION class variable. The region table entry is (offsets
# from the beginning of the entry, since it could be in multiple places):
#
#      0 0x00000 16-byte MSFT GUID
#     16 0x00010 Offset of the actual metadata region (uint64_t)
#
# When we find the METAREGION table entry, we need to grab that offset
# and start examining the region structure at that point. That
# consists of a metadata table of structures, which point to places in
# the data in an unstructured space that follows. The header is
# (offsets relative to the region start):
#
#      0 0x00000 8-byte signature ('metadata')
#      . . .
#     16 0x00010 2-byte entry count (up to 2047 entries max)
#
# This header is followed by the specified number of metadata entry
# structures, identified by GUID:
#
#      0 0x00000 16-byte MSFT GUID
#     16 0x00010 4-byte offset (uint32_t, relative to the beginning of
#                the metadata region)
#
# We need to find the "Virtual Disk Size" metadata item, identified by
# the GUID in the VIRTUAL_DISK_SIZE class variable, grab the offset,
# add it to the offset of the metadata region, and examine that 8-byte
# chunk of data that follows.
#
# The "Virtual Disk Size" is a naked uint64_t which contains the size
# of the virtual disk, and is our ultimate target here.
#
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83e061f8-f6e2-4de1-91bd-5d518a43d477
class VHDXInspector(FileInspector):
    """MS VHDX Format

    This requires some complex parsing of the stream. The first 256KiB
    of the image is stored to get the header and region information,
    and then we capture the first metadata region to read those
    records, find the location of the virtual size data and parse
    it. This needs to store the metadata table entries up until the
    VDS record, which may consist of up to 2047 32-byte entries at
    max.  Finally, it must store a chunk of data at the offset of the
    actual VDS uint64.

    """
    NAME = 'vhdx'
    METAREGION = '8B7CA206-4790-4B9A-B8FE-575F050F886E'
    VIRTUAL_DISK_SIZE = '2FA54224-CD1B-4876-B211-5DBED83BF4B8'
    VHDX_METADATA_TABLE_MAX_SIZE = 32 * 2048  # From qemu

    def _initialize(self):
        self.new_region('ident', CaptureRegion(0, 32))
        self.new_region('header', CaptureRegion(192 * 1024, 64 * 1024))
        self.add_safety_check(SafetyCheck.null())

    def post_process(self):
        # After reading a chunk, we may have the following conditions:
        #
        # 1. We may have just completed the header region, and if so,
        #    we need to immediately read and calculate the location of
        #    the metadata region, as it may be starting in the same
        #    read we just did.
        # 2. We may have just completed the metadata region, and if so,
        #    we need to immediately calculate the location of the
        #    "virtual disk size" record, as it may be starting in the
        #    same read we just did.
        if self.region('header').complete and not self.has_region('metadata'):
            region = self._find_meta_region()
            if region:
                self.new_region('metadata', region)
        elif self.has_region('metadata') and not self.has_region('vds'):
            region = self._find_meta_entry(self.VIRTUAL_DISK_SIZE)
            if region:
                self.new_region('vds', region)

    @property
    def format_match(self):
        return self.region('ident').data.startswith(b'vhdxfile')

    @staticmethod
    def _guid(buf):
        """Format a MSFT GUID from the 16-byte input buffer."""
        guid_format = '<IHHBBBBBBBB'
        return '%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X' % (
            struct.unpack(guid_format, buf))

    def _find_meta_region(self):
        # The region table entries start after a 16-byte table header
        region_entry_first = 16

        # Parse the region table header to find the number of regions
        regi, cksum, count, reserved = struct.unpack(
            '<IIII', self.region('header').data[:16])
        if regi != 0x69676572:
            raise ImageFormatError('Region signature not found at %x' % (
                self.region('header').offset))

        if count >= 2048:
            raise ImageFormatError('Region count is %i (limit 2047)' % count)

        # Process the regions until we find the metadata one; grab the
        # offset and return
        self._trace('Region entry first is %x', region_entry_first)
        self._trace('Region entries %i', count)
        meta_offset = 0
        for i in range(0, count):
            entry_start = region_entry_first + (i * 32)
            entry_end = entry_start + 32
            entry = self.region('header').data[entry_start:entry_end]
            self._trace('Entry offset is %x', entry_start)

            # GUID is the first 16 bytes
            guid = self._guid(entry[:16])
            if guid == self.METAREGION:
                # This entry is the metadata region entry
                meta_offset, meta_len, meta_req = struct.unpack(
                    '<QII', entry[16:])
                self._trace('Meta entry %i specifies offset: %x',
                            i, meta_offset)
                # NOTE(danms): The meta_len in the region descriptor is the
                # entire size of the metadata table and data. This can be
                # very large, so we should only capture the size required
                # for the maximum length of the table, which is one 32-byte
                # table header, plus up to 2047 32-byte entries.
                meta_len = 2048 * 32
                return CaptureRegion(meta_offset, meta_len)

        self._trace('Did not find metadata region')
        return None

    def _find_meta_entry(self, desired_guid):
        meta_buffer = self.region('metadata').data
        if len(meta_buffer) < 32:
            # Not enough data yet for full header
            return None

        # Make sure we found the metadata region by checking the signature
        sig, reserved, count = struct.unpack('<8sHH', meta_buffer[:12])
        if sig != b'metadata':
            raise ImageFormatError(
                'Invalid signature for metadata region: %r' % sig)

        entries_size = 32 + (count * 32)
        if len(meta_buffer) < entries_size:
            # Not enough data yet for all metadata entries. This is not
            # strictly necessary as we could process whatever we have until
            # we find the V-D-S one, but there are only 2047 32-byte
            # entries max (~64k).
            return None

        if count >= 2048:
            raise ImageFormatError(
                'Metadata item count is %i (limit 2047)' % count)

        for i in range(0, count):
            entry_offset = 32 + (i * 32)
            guid = self._guid(meta_buffer[entry_offset:entry_offset + 16])
            if guid == desired_guid:
                # Found the item we are looking for by id.
                # Stop our region from capturing
                item_offset, item_length, _reserved = struct.unpack(
                    '<III',
                    meta_buffer[entry_offset + 16:entry_offset + 28])
                item_length = min(item_length,
                                  self.VHDX_METADATA_TABLE_MAX_SIZE)
                self.region('metadata').length = len(meta_buffer)
                self._trace('Found entry at offset %x', item_offset)
                # Metadata item offset is from the beginning of the metadata
                # region, not the file.
                return CaptureRegion(
                    self.region('metadata').offset + item_offset,
                    item_length)

        self._trace('Did not find guid %s', desired_guid)
        return None

    @property
    def virtual_size(self):
        # Until we have found the offset and have enough metadata buffered
        # to read it, return "unknown"
        if not self.has_region('vds') or not self.region('vds').complete:
            return 0

        size, = struct.unpack('<Q', self.region('vds').data)
        return size


# The VMDK format comes in a large number of variations, but the
# single-file 'monolithicSparse' version 4 one is mostly what we care
# about. It contains a 512-byte little-endian header, followed by a
# variable-length "descriptor" region of text. The header looks like:
#
#   Dec  Hex  Name
#     0 0x00  4-byte magic string 'KDMV'
#     4 0x04  Version (uint32_t)
#     8 0x08  Flags (uint32_t, unused by us)
#    12 0x0C  Number of 512 byte sectors in the disk (uint64_t)
#    20 0x14  Granularity (uint64_t, unused by us)
#    28 0x1C  Descriptor offset in 512-byte sectors (uint64_t)
#    36 0x24  Descriptor size in 512-byte sectors (uint64_t)
#    44 0x2C  Number of GTEs per GT (uint32_t)
#    48 0x30  Redundant level 0 metadata offset (uint64_t)
#    56 0x38  Pointer to level 0 of metadata (uint32_t)
#
# After we have the header, we need to find the descriptor region,
# which starts at the sector identified in the "descriptor offset"
# field, and is "descriptor size" 512-byte sectors long. Once we have
# that region, we need to parse it as text, looking for the
# createType=XXX line that specifies the mechanism by which the data
# extents are stored in this file. We only support the
# "monolithicSparse" format, so we just need to confirm that this file
# contains that specifier.
#
# https://www.vmware.com/app/vmdk/?src=vmdk
class VMDKInspector(FileInspector):
    """vmware VMDK format (monolithicSparse and streamOptimized variants only)

    This needs to store the 512 byte header and the descriptor region
    which should be just after that. The descriptor region is some
    variable number of 512 byte sectors, but is just text defining the
    layout of the disk.
    """

    NAME = 'vmdk'
    # The beginning and max size of the descriptor is also hardcoded in Qemu
    # at 0x200 and 1MB - 1
    DESC_OFFSET = 0x200
    DESC_MAX_SIZE = (1 << 20) - 1
    GD_AT_END = 0xffffffffffffffff
    # This is the minimum amount of data we need to read to recognize and
    # process a "Hosted Sparse Extent" header
    MIN_SPARSE_HEADER = 64
    MARKER_EOS = 0
    MARKER_FOOTER = 3

    def _initialize(self):
        self.desc_text = None
        # This is the header for "Hosted Sparse Extent" type files. It may
        # or may not be used, depending on what kind of VMDK we are about to
        # read.
        self.new_region('header',
                        CaptureRegion(0, 512,
                                      min_length=self.MIN_SPARSE_HEADER))
        # The descriptor starts from the beginning in the some of the older
        # formats, but we do not know which one we are reading yet. This
        # will be deleted and re-created if we are reading one of the formats
        # that embeds it later.
        self.new_region('descriptor',
                        CaptureRegion(0, self.DESC_MAX_SIZE, min_length=4))
        self.add_safety_check(
            SafetyCheck('descriptor', self.check_descriptor))

    def _parse_sparse_header(self, region, offset=0):
        (sig, ver, _flags, _sectors, _grain, desc_sec, desc_num,
            _numGTEsperGT, _rgdOffset, gdOffset) = struct.unpack(
            '<4sIIQQQQIQQ',
            self.region(region).data[offset:offset + self.MIN_SPARSE_HEADER])
        return sig, ver, desc_sec, desc_num, gdOffset

    def post_process(self):
        # If we have just completed the header region, we need to calculate
        # the location and length of the descriptor, which should immediately
        # follow and may have been partially-read in this read. If the header
        # was previously read and that region was deleted, we have nothing
        # to do here.
        if not self.has_region('header') or not self.region('header').complete:
            return

        sig, ver, desc_sec, desc_num, gdOffset = (
            self._parse_sparse_header('header'))

        try:
            is_text = True
            for char in self.region('header').data.decode('ascii'):
                if not char.isprintable() and not char.isspace():
                    is_text = False
                    break
        except UnicodeDecodeError:
            is_text = False

        if sig != b'KDMV':
            if is_text:
                # We assume that if everything we have read so far is ASCII
                # text and the header doesn't have the sparse signature,
                # this must (or may be) a text-only VMDK descriptor file,
                # which still needs to be parsed and checked since qemu will
                # support it.
                self.delete_region('header')
                return
            raise ImageFormatError('Signature KDMV not found: %r' % sig)

        if ver not in (1, 2, 3):
            raise ImageFormatError('Unsupported format version %i' % ver)

        if gdOffset == self.GD_AT_END and not self.has_region('footer'):
            # This means we have a footer, which takes precedence over the
            # header, which we cannot support since we stream.
            self.new_region('footer', EndCaptureRegion(1536))
            self.add_safety_check(SafetyCheck('footer', self.check_footer))

        # Since we parse both desc_sec and desc_num (the location of the
        # VMDK's descriptor, expressed in 512 bytes sectors) we enforce a
        # check on the bounds to create a reasonable CaptureRegion. This
        # is similar to how it's done in qemu.
        desc_offset = desc_sec * 512
        desc_size = min(desc_num * 512, self.DESC_MAX_SIZE)
        if desc_offset != self.DESC_OFFSET:
            raise ImageFormatError("Wrong descriptor location")

        # If we parsed a valid sparse header and we still have the original
        # descriptor region at BOF, recreate it with the actual offset of the
        # embedded one.
        if self.region('descriptor').offset == 0:
            self.delete_region('descriptor')
            self.new_region('descriptor',
                            CaptureRegion(desc_offset, desc_size))

    def region_complete(self, region_name):
        if region_name == 'descriptor':
            self._parse_descriptor()

    def _parse_descriptor(self):
        try:
            # The sparse descriptor is null-padded to 512 bytes. Find the
            # first one and use it as the end of the text string.
            desc_data = self.region('descriptor').data
            pad_idx = desc_data.index(b'\x00')
            desc_data = desc_data[:pad_idx]
        except ValueError:
            # Not a sparse descriptor, proceed to decode as test
            pass
        try:
            # Descriptor is actually case-insensitive ASCII text
            desc_text = desc_data.decode('ascii').lower()
        except UnicodeDecodeError:
            LOG.error('VMDK descriptor failed to decode as ASCII')
            return

        try:
            type_idx = desc_text.index('createtype="') + len('createtype="')
            type_end = desc_text.find('"', type_idx)
        except ValueError:
            # This means we did not find the createType= header, which is
            # fatal, so we should refuse this.
            vmdktype = 'formatnotfound'
        else:
            # Make sure we don't grab and log a huge chunk of data in a
            # maliciously-formatted descriptor region
            if type_end - type_idx < 64:
                vmdktype = desc_text[type_idx:type_end]
            else:
                vmdktype = 'formatnotfound'

        self.desc_text = desc_text
        self.vmdktype = vmdktype

    @property
    def format_match(self):
        if self.has_region('header'):
            return self.region('header').data.startswith(b'KDMV')
        else:
            return self.vmdktype != 'formatnotfound'

    @property
    def virtual_size(self):
        if not self.desc_text:
            # Not enough data yet
            return 0

        if self.vmdktype not in ('monolithicsparse', 'streamoptimized'):
            LOG.warning('Unsupported VMDK format %r', self.vmdktype)
            return 0

        # If we have the descriptor, we definitely have the header
        _sig, _ver, _flags, sectors, _grain, _desc_sec, _desc_num = (
            struct.unpack('<IIIQQQQ', self.region('header').data[:44]))

        return sectors * 512

    def check_descriptor(self):
        if not self.desc_text:
            raise SafetyViolation(_('No descriptor found'))

        extent_access = ('rw', 'rdonly', 'noaccess')
        header_fields = []
        extents = []
        ddb = []

        if self.vmdktype not in ('monolithicsparse', 'streamoptimized'):
            LOG.warning('Unsupported VMDK format %r', self.vmdktype)
            raise SafetyViolation('Unsupported subformat')

        # NOTE(danms): Cautiously parse the VMDK descriptor. Each line must
        # be something we understand, otherwise we refuse it.
        for line in [x.strip() for x in self.desc_text.split('\n')]:
            if line.startswith('#') or not line:
                # Blank or comment lines are ignored
                continue
            elif line.startswith('ddb'):
                # DDB lines are allowed (but not used by us)
                ddb.append(line)
            elif '=' in line and ' ' not in line.split('=')[0]:
                # Header fields are a single word followed by an '=' and some
                # value
                header_fields.append(line)
            elif line.split(' ')[0] in extent_access:
                # Extent lines start with one of the three access modes
                extents.append(line)
            else:
                # Anything else results in a rejection
                LOG.error('Unsupported line %r in VMDK descriptor', line)
                raise SafetyViolation(_('Invalid VMDK descriptor data'))

        # Check all the extent lines for concerning content
        for extent_line in extents:
            if '/' in extent_line:
                LOG.error('Extent line %r contains unsafe characters',
                          extent_line)
                raise SafetyViolation(_('Invalid extent filenames found'))

        if not extents:
            LOG.error('VMDK file specified no extents')
            raise SafetyViolation(_('No extents found'))

    def check_footer(self):
        h_sig, h_ver, h_desc_sec, h_desc_num, h_goff = (
            self._parse_sparse_header('header'))
        f_sig, f_ver, f_desc_sec, f_desc_num, f_goff = (
            self._parse_sparse_header('footer', 512))

        if h_sig != f_sig:
            raise SafetyViolation(
                _('Header and footer signature do not match'))
        if h_ver != f_ver:
            raise SafetyViolation(_('Header and footer versions do not match'))
        if h_desc_sec != f_desc_sec or h_desc_num != f_desc_num:
            raise SafetyViolation(
                _('Footer specifies a different descriptor than header'))
        if f_goff == self.GD_AT_END:
            raise SafetyViolation(_('Footer indicates another footer'))

        pad = b'\x00' * 496
        val, size, typ, zero = struct.unpack(
            '<QII496s',
            self.region('footer').data[:512])
        if size != 0 or typ != self.MARKER_FOOTER or zero != pad:
            raise SafetyViolation(_('Footer marker is invalid'))

        val, size, typ, zero = struct.unpack(
            '<QII496s',
            self.region('footer').data[-512:])
        if val != 0 or size != 0 or typ != self.MARKER_EOS or zero != pad:
            raise SafetyViolation(_('End-of-stream marker is invalid'))


# The VirtualBox VDI format consists of a 512-byte little-endian
# header, some of which we care about:
#
#  Dec   Hex  Name
#   64  0x40  4-byte Magic (0xbeda107f)
#   . . .
#  368 0x170  Size in bytes (uint64_t)
#
# https://github.com/qemu/qemu/blob/master/block/vdi.c
class VDIInspector(FileInspector):
    """VirtualBox VDI format

    This only needs to store the first 512 bytes of the image.
    """
    NAME = 'vdi'

    def _initialize(self):
        self.new_region('header', CaptureRegion(0, 512))
        self.add_safety_check(SafetyCheck.null())

    @property
    def format_match(self):
        if not self.region('header').complete:
            return False

        signature, = struct.unpack('<I', self.region('header').data[0x40:0x44])
        return signature == 0xbeda107f

    @property
    def virtual_size(self):
        if not self.region('header').complete:
            return 0
        if not self.format_match:
            return 0

        size, = struct.unpack('<Q', self.region('header').data[0x170:0x178])
        return size


class ISOInspector(FileInspector):
    """ISO 9660 and UDF format

    we need to check the first 32KB + descriptor size
    to look for the ISO 9660 or UDF signature.

    http://wiki.osdev.org/ISO_9660
    http://wiki.osdev.org/UDF
    mkisofs --help  | grep udf

    The Universal Disc Format or UDF is the filesystem used on DVDs and
    Blu-Ray discs.UDF is an extension of ISO 9660 and shares the same
    header structure and initial layout.

    Like the CDFS(ISO 9660) file system,
    the UDF file system uses a 2048 byte sector size,
    and it designates that the first 16 sectors can be used by the OS
    to store proprietary data or boot logic.

    That means we need to check the first 32KB + descriptor size
    to look for the ISO 9660 or UDF signature.
    both formats have an extent based layout, so we can't determine
    ahead of time where the descriptor will be located.

    fortunately, the ISO 9660 and UDF formats have a Primary Volume Descriptor
    located at the beginning of the image, which contains the volume size.

    """
    NAME = 'iso'

    def _initialize(self):
        self.new_region('system_area', CaptureRegion(0, 32 * units.Ki))
        self.new_region('header', CaptureRegion(32 * units.Ki, 2 * units.Ki))
        self.add_safety_check(SafetyCheck.null())

    @property
    def format_match(self):
        if not self.complete:
            return False
        signature = self.region('header').data[1:6]
        return signature in (b'CD001', b'NSR02', b'NSR03')

    @property
    def virtual_size(self):
        if not self.complete:
            return 0
        if not self.format_match:
            return 0

        # the header size is 2KB or 1 sector
        # the first header field is the descriptor type which is 1 byte
        # the second field is the standard identifier which is 5 bytes
        # the third field is the version which is 1 byte
        # the rest of the header contains type specific data is 2041 bytes
        # see http://wiki.osdev.org/ISO_9660#The_Primary_Volume_Descriptor

        # we need to check that the descriptor type is 1
        # to ensure that this is a primary volume descriptor
        descriptor_type = self.region('header').data[0]
        if descriptor_type != 1:
            return 0
        # The size in bytes of a logical block is stored at offset 128
        # and is 2 bytes long encoded in both little and big endian
        # int16_LSB-MSB so the field is 4 bytes long
        logical_block_size_data = self.region('header').data[128:132]
        # given the encoding we only need to read half the field so we
        # can use the first 2 bytes which are the little endian part
        # this is normally 2048 or 2KB but we need to check as it can be
        # different according to the ISO 9660 standard.
        logical_block_size, = struct.unpack('<H', logical_block_size_data[:2])
        # The volume space size is the total number of logical blocks
        # and is stored at offset 80 and is 8 bytes long
        # as with the logical block size the field is encoded in both
        # little and big endian as an int32_LSB-MSB
        volume_space_size_data = self.region('header').data[80:88]
        # given the encoding we only need to read half the field so we
        # can use the first 4 bytes which are the little endian part
        volume_space_size, = struct.unpack('<L', volume_space_size_data[:4])
        # the virtual size is the volume space size * logical block size
        return volume_space_size * logical_block_size


# GPT is a superset of legacy MBR and we can detect the two with the same
# inspector. There may be more we can safety check for GPT, but detecting
# both formats is simpler.
# https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html
class GPTInspector(FileInspector):
    NAME = 'gpt'
    MBR_SIGNATURE = 0xAA55
    MBR_PTE_START = 446
    MEDIA_TYPE_FDISK = 0xF8

    def _initialize(self):
        self.new_region('mbr', CaptureRegion(0, 512))
        # TODO(danms): If we start inspecting the contents of the GPT
        # structures themselves, we need to realize that they are block-aligned
        # and not necessarily right after the PMBR at 512 bytes.
        # self.new_region('gpt', CaptureRegion(512, 512))
        # If we detect that this is a GPT, we may want to capture the backup
        # and assert that it is equivalent.
        # TODO(danms): Maybe add this region and associated checks:
        # self.new_region('gpt_backup', EndCaptureRegion(512))
        self.add_safety_check(SafetyCheck('mbr', self.check_mbr_partitions))

    def _check_for_fat(self):
        # A FAT filesystem looks like an MBR, but actually starts with a VBR,
        # which has the same signature as an MBR, but with more specifics in
        # the BPB (BIOS Parameter Block).
        boot_sector = self.region('mbr').data
        # num_fats is almost always 2 (never more or less) for any filesystem
        # not super tiny (think 1980s ramdisk)
        num_fats = boot_sector[0x10]
        # Media descriptor will basically always be "a fixed disk" for any of
        # our purposes, not a floppy disk
        media_desc = boot_sector[0x15]
        return (num_fats == 2 and media_desc == self.MEDIA_TYPE_FDISK)

    @property
    def format_match(self):
        if not self.region('mbr').complete:
            return False
        # Check to see if this looks like a VBR from a FAT filesystem so we
        # can exclude it
        is_fat = self._check_for_fat()
        mbr_sig, = struct.unpack('<H', self.region('mbr').data[510:512])
        return mbr_sig == self.MBR_SIGNATURE and not is_fat

    def check_mbr_partitions(self):
        valid_partitions = []
        found_gpt = False
        for i in range(4):
            pte_start = self.MBR_PTE_START + (16 * i)
            pte = self.region('mbr').data[pte_start:pte_start + 16]
            (boot, starth, starts, startt, ostype,
             endh, ehds, endt, startlba, sizelba) = struct.unpack(
                '<B3BB3BII', pte)
            if boot not in (0x00, 0x80):
                raise SafetyViolation('MBR PTE %i has invalid boot flag' % i)
            if ostype != 0:
                valid_partitions.append(i)
            if ostype == 0xEE:
                found_gpt = True
                if (starth, starts, startt) != (0x00, 0x02, 0x00):
                    raise SafetyViolation('GPT MBR has invalid start CHS')
                if startlba != 0x00000001:
                    raise SafetyViolation('GPT MBR has invalid start LBA')
        if found_gpt and valid_partitions != [0]:
            raise SafetyViolation('GPT MBR defines invalid extra partitions')
        if not valid_partitions:
            raise SafetyViolation('GPT MBR has no partitions defined')


# The LUKSv1 format consists of a header with some metadata and key
# information followed by a bulk non-sparse data payload which is the
# encyrpted disk image.
# https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf
# LUKSv2 is a different but similar spec, which is not yet covered here (or
# in qemu).
class LUKSInspector(FileInspector):
    NAME = 'luks'

    def _initialize(self):
        self.new_region('header', CaptureRegion(0, 592))
        self.add_safety_check(SafetyCheck('version', self.check_version))

    @property
    def format_match(self):
        return self.region('header').data[:6] == b'LUKS\xBA\xBE'

    @property
    def header_items(self):
        fields = struct.unpack('>6sh32s32s32sI',
                               self.region('header').data[:108])
        names = ['magic', 'version', 'cipher_alg', 'cipher_mode', 'hash',
                 'payload_offset']
        return dict(zip(names, fields))

    def check_version(self):
        header = self.header_items
        if header['version'] != 1:
            raise SafetyViolation(
                'LUKS version %i is not supported' % header['version'])

    @property
    def virtual_size(self):
        # NOTE(danms): This will not be correct until/unless the whole stream
        # has been read, since all we have is (effectively the size of the
        # header. This is similar to how RawFileInspector works.
        return super().virtual_size - self.header_items['payload_offset'] * 512


class InspectWrapper:
    """A file-like object that wraps another and detects the format.

    This passes chunks to a group of format inspectors (default: all)
    while reading. After the stream is finished (or enough has been read to
    make a confident decision), the format attribute will provide the
    inspector object that matched.

    :param source: The file-like input stream to wrap
    :param expected_format: The format name anticipated to match, if any.
                            If set to a format name, reading of the stream will
                            be interrupted if the matching inspector raises
                            an error (indicting a mismatch or any other
                            problem). This allows the caller to abort before
                            all data is processed.
    :param allowed_formats: A list of format names that limits the inspector
                            objects that will be used. This may be a security
                            hole if used improperly, but may be used to limit
                            the detected formats to some smaller scope.
    """
    def __init__(self, source, expected_format=None, allowed_formats=None):
        self._source = source
        self._expected_format = expected_format
        self._errored_inspectors = set()
        self._inspectors = {v() for k, v in ALL_FORMATS.items()
                            if not allowed_formats or k in allowed_formats}
        self._finished = False

    def __iter__(self):
        return self

    def _process_chunk(self, chunk):
        for inspector in [i for i in self._inspectors
                          if i not in self._errored_inspectors]:
            try:
                inspector.eat_chunk(chunk)
            except Exception as e:
                if inspector.NAME == self._expected_format:
                    # If our desired inspector has failed, we cannot continue
                    raise
                # Absolutely do not allow the format inspector to break
                # our streaming of the image for non-expected formats. If we
                # failed, just stop trying, log and keep going.
                if not self._expected_format:
                    # If we are expecting to parse a specific format, we do
                    # not need to log scary messages about the other formats
                    # failing to parse the data as expected.
                    LOG.debug('Format inspector for %s does not match, '
                              'excluding from consideration (%s)',
                              inspector.NAME, e)
                self._errored_inspectors.add(inspector)
            else:
                # If we are expecting a format, have read enough data to
                # satisfy that format's inspector, and no match is detected,
                # abort the stream immediately to save having to read the
                # entire thing before we signal the mismatch.
                if (inspector.NAME == self._expected_format and
                        inspector.complete and not inspector.format_match):
                    raise ImageFormatError(
                        'Content does not match expected format %r' % (
                            inspector.NAME))

    def __next__(self):
        try:
            chunk = next(self._source)
        except StopIteration:
            self._finish()
            raise
        self._process_chunk(chunk)
        return chunk

    def read(self, size):
        chunk = self._source.read(size)
        self._process_chunk(chunk)
        return chunk

    def _finish(self):
        for inspector in self._inspectors:
            inspector.finish()
        self._finished = True

    def close(self):
        if hasattr(self._source, 'close'):
            self._source.close()
        self._finish()

    @property
    def formats(self):
        """The formats (potentially multiple) determined from the content.

        This is just like format, but returns a list of formats that matched,
        which may be more than one if appropriate. This should generally not
        be used as it is safer to allow one and only one format. However, there
        are situations where multiple formats could be detected legitimately
        (i.e. bootable ISOs) where we need to expose the case where we have
        found more than one. If no specific matches are made, this will return
        a list with just the Raw inspector, but will never include Raw in
        combination with others.

        This will be None if a decision has not been reached.
        """
        non_raw = {i for i in self._inspectors if i.NAME != 'raw'}
        complete = all([i.complete for i in non_raw])
        matches = [i for i in non_raw if i.format_match]
        if not complete and not self._finished:
            # We do not know what our format is if we're still in progress
            # of reading the stream and have incomplete inspectors. However,
            # if EOF has been signaled, then we can assume the incomplete ones
            # are not matches.
            return None
        if not matches:
            try:
                # If nothing *specific* matched, we return the raw format to
                # indicate that we do not recognize this content at all.
                return [x for x in self._inspectors if str(x) == 'raw']
            except IndexError:
                raise ImageFormatError(
                    'Content does not match any allowed format')
        return matches

    @property
    def format(self):
        """The format determined from the content.

        If this is None, a decision has not been reached. Otherwise,
        it is a FileInspector that matches (which may be RawFileInspector
        if no other formats matched and enough of the stream has been read
        to make that determination). If more than one format matched, then
        ImageFormatError is raised. If the allowed_formats was constrained
        and raw was not included, then this will raise ImageFormatError to
        indicate that no suitable match was found.
        """
        matches = self.formats
        if matches is None:
            return matches
        elif len(matches) > 1:
            # Multiple format matches mean that not only can we not return a
            # decision here, but also means that there may be something
            # nefarious going on (i.e. hiding one header in another).
            raise ImageFormatError('Multiple formats detected: %s' % ','.join(
                str(i) for i in matches))
        else:
            try:
                # The expected outcome of this is a single match of something
                # specific
                return matches[0]
            except IndexError:
                raise ImageFormatError(
                    'Content does not match any allowed format')


ALL_FORMATS = {
    'raw': RawFileInspector,
    'qcow2': QcowInspector,
    'vhd': VHDInspector,
    'vhdx': VHDXInspector,
    'vmdk': VMDKInspector,
    'vdi': VDIInspector,
    'qed': QEDInspector,
    'iso': ISOInspector,
    'gpt': GPTInspector,
    'luks': LUKSInspector,
}


def get_inspector(format_name):
    """Returns a FormatInspector class based on the given name.

    :param format_name: The name of the disk_format (raw, qcow2, etc).
    :returns: A FormatInspector or None if unsupported.
    """

    return ALL_FORMATS.get(format_name)


def detect_file_format(filename):
    """Attempts to detect the format of a file.

    This runs through a file one time, running all the known inspectors in
    parallel. It stops reading the file once all of them matches or all of
    them are sure they don't match.

    :param filename: The path to the file to inspect.
    :returns: A FormatInspector instance matching the file.
    :raises: ImageFormatError if multiple formats are detected.
    """
    with open(filename, 'rb') as f:
        wrapper = InspectWrapper(f)
        try:
            for _chunk in _chunked_reader(wrapper, 4096):
                if wrapper.format:
                    return wrapper.format
        finally:
            wrapper.close()
        return wrapper.format
