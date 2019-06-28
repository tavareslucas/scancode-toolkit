#
# Copyright (c) 2019 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/scancode-toolkit/
# The ScanCode software is licensed under the Apache License version 2.0.
# Data generated with ScanCode require an acknowledgment.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with ScanCode or any ScanCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with ScanCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  ScanCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  ScanCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/scancode-toolkit/ for support and download.

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import os
from collections import OrderedDict

from scancode.resource import Codebase

from packages_test_utils import PackageTester

from packagedcode import conda


class TestConda(PackageTester):
    test_data_dir = os.path.join(os.path.dirname(__file__), 'data')

    def test_parse_get_varialble(self):
        test_file = self.get_test_loc('conda/meta.yaml')
        results = conda.get_variables(test_file)
        assert OrderedDict([(u'version', u'0.45.0'), (u'sha256', u'bc7512f2eef785b037d836f4cc6faded457ac277f75c6e34eccd12da7c85258f')])==results

    def test_get_yaml_data(self):
        test_file = self.get_test_loc('conda/meta.yaml')
        results = conda.get_yaml_data(test_file)
        assert  (u'package', OrderedDict([(u'name', u'abeona'), (u'version', u'0.45.0')]))==results.items()[0]

    def test_parse(self):
        test_file = self.get_test_loc('conda/meta.yaml')
        package = conda.parse(test_file)
        expected_loc = self.get_test_loc('conda/meta.yaml.expected.json')
        self.check_package(package, expected_loc, regen=False)

    def test_root_dir(self):
        test_file = self.get_test_loc('conda/requests-kerberos-0.8.0-py35_0.tar.bz2-extract/info/recipe.tar-extract/recipe/meta.yaml')
        test_dir = self.get_test_loc('conda/requests-kerberos-0.8.0-py35_0.tar.bz2-extract')
        codebase = Codebase(test_dir)
        manifest_resource = codebase.get_resource_from_path(test_file, absolute=True)
        proot = conda.CondaPackage.get_package_root(manifest_resource, codebase)
        assert test_dir == proot.location
