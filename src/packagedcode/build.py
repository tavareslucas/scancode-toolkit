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

import logging

import attr

from commoncode import filetype
from packagedcode import models
from commoncode import fileutils


TRACE = False

logger = logging.getLogger(__name__)

if TRACE:
    import sys
    logging.basicConfig(stream=sys.stdout)
    logger.setLevel(logging.DEBUG)


"""
Detect as Packages common build tools and environment such as Make, Autotools,
gradle, Buck, Bazel, Pants, etc.
"""


@attr.s()
class BazelPackage(models.Package):
    metafiles = ('BUILD',)
    default_type = 'bazel'

    @classmethod
    def recognize(cls, location):
        """
        Return a Package object or None.
        """
        if not cls._is_manifest(location):
            return

        # we use the parent directory as a name
        name = fileutils.file_name(fileutils.parent_directory(location))
        # we could use checksums as version in the future
        version = None

        # there is an optional array of license file names in targets that we could use
        # declared_license = None
        # there is are dependencies we could use
        # dependencies = []
        return cls(
            name=name,
            version=version,
        )

    def compute_normalized_license(self):
        return

    @classmethod
    def get_package_root(cls, manifest_resource, codebase):
        return manifest_resource.parent(codebase)

    @classmethod
    def _is_manifest(cls, location):
        return (filetype.is_file(location) 
            and fileutils.file_name(location)==cls.metafiles[0])



@attr.s()
class BuckPackage(BazelPackage):
    metafiles = ('BUCK',)
    default_type = 'buck'


