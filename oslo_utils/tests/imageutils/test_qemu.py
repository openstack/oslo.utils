# Copyright (C) 2012 Yahoo! Inc.
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

from oslo_utils import imageutils
from oslo_utils.tests import base as test_base


class QemuImgInfoTestCase(test_base.BaseTestCase):
    def test_qemu_img_unsupported(self):
        self.assertRaises(
            ValueError, imageutils.QemuImgInfo, '', format='human'
        )

    def test_qemu_img_info(self):
        img_output = '''{
                       "virtual-size": 41126400,
                       "filename": "fake_img",
                       "cluster-size": 65536,
                       "format": "qcow2",
                       "actual-size": 13168640,
                       "format-specific": {"data": {"foo": "bar"}},
                       "encrypted": true
                      }'''
        image_info = imageutils.QemuImgInfo(img_output, format='json')
        self.assertEqual(41126400, image_info.virtual_size)
        self.assertEqual('fake_img', image_info.image)
        self.assertEqual(65536, image_info.cluster_size)
        self.assertEqual('qcow2', image_info.file_format)
        self.assertEqual(13168640, image_info.disk_size)
        self.assertEqual("bar", image_info.format_specific["data"]["foo"])
        self.assertEqual('yes', image_info.encrypted)
        # test for Bug #1996426
        expected_str = "format_specific: {'data': {'foo': 'bar'}}"
        self.assertIn(expected_str, str(image_info))

    def test_qemu_img_info_blank(self):
        img_output = '{}'
        image_info = imageutils.QemuImgInfo(img_output, format='json')
        self.assertIsNone(image_info.virtual_size)
        self.assertIsNone(image_info.image)
        self.assertIsNone(image_info.cluster_size)
        self.assertIsNone(image_info.file_format)
        self.assertIsNone(image_info.disk_size)
        self.assertIsNone(image_info.format_specific)
        self.assertIsNone(image_info.encrypted)
