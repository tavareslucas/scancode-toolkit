#
# Copyright (c) 2018 nexB Inc. and others. All rights reserved.
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
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import attr
from license_expression import Licensing

from packagedcode import get_package_class
from packagedcode import models
from plugincode.post_scan import post_scan_impl
from plugincode.post_scan import PostScanPlugin
from plugincode.scan import scan_impl
from plugincode.scan import ScanPlugin
from scancode import CommandLineOption
from scancode import POST_SCAN_GROUP
from scancode import SCAN_GROUP


# Tracing flags
TRACE = False


def logger_debug(*args):
    pass


if TRACE:
    import logging
    import sys

    logger = logging.getLogger(__name__)
    logging.basicConfig(stream=sys.stdout)
    logger.setLevel(logging.DEBUG)

    def logger_debug(*args):
        return logger.debug(' '.join(isinstance(a, unicode) and a or repr(a) for a in args))


@scan_impl
class PackageScanner(ScanPlugin):
    """
    Scan a Resource for Package manifests and report these as "packages" at the
    right file or directory level.
    """

    resource_attributes = dict(packages=attr.ib(default=attr.Factory(list), repr=False))

    sort_order = 6

    required_plugins = ['scan:licenses', ]

    options = [
        CommandLineOption(('-p', '--package',),
            is_flag=True, default=False,
            help='Scan <input> for package manifests and packages.',
            # yes, this is showed as a SCAN plugin in doc/help
            help_group=SCAN_GROUP,
            sort_order=20),
    ]

    def is_enabled(self, package, **kwargs):
        return package

    def get_scanner(self, **kwargs):
        """
        Return a scanner callable to scan a Resource for packages.
        """
        from scancode.api import get_package_info
        return get_package_info

    def process_codebase(self, codebase, **kwargs):
        """
        Move package manifest scan information to the proper file or
        directory level given a package type.
        """
        if codebase.has_single_resource:
            # What if we scanned a single file and we do not have a root proper?
            return

        for resource in codebase.walk(topdown=False):
            # only files can have a manifest
            if not resource.is_file:
                continue

            if resource.is_root:
                continue

            packages_info = resource.packages
            if not packages_info:
                continue

            # NOTE: we are dealing with a single file therefore there should be
            # only be a single package detected. But some package manifests can
            # document more than one package at a time such as multiple
            # arches/platforms for a gempsec or multiple sub package (with
            # "%package") in an RPM .spec file.
            for package_info in packages_info:
                package_class = get_package_class(package_info)
                new_package_root = package_class.get_package_root(resource, codebase)

                if not new_package_root:
                    # this can happen if we scan a single resource that is a package manifest
                    continue

                if new_package_root == resource:
                    continue

                # here new_package_root != resource:

                # What if the target resource (e.g. a parent) is the root and we are in stripped root mode?
                if new_package_root.is_root and codebase.strip_root:
                    continue

                # Determine if this package applies to more than just the manifest
                # file (typically it means the whole parent directory is the
                # package) and if yes:
                # 1. fetch this resource
                # 2. move the package data to this new resource
                # 3. set the manifest_path if needed.
                # 4. save.

                # here we have a relocated Resource and we compute the manifest path
                # relative to the new package root
                new_package_root_path = new_package_root.path and new_package_root.path.strip('/')
                if new_package_root_path:
                    _, _, manifest_path = resource.path.partition(new_package_root_path)
                    # note we could have also deserialized and serialized again instead
                    package_info['manifest_path'] = manifest_path.lstrip('/')

                new_package_root.packages.append(package_info)
                codebase.save_resource(new_package_root)
                resource.packages = []
                codebase.save_resource(resource)


@post_scan_impl
class PackageSummary(PostScanPlugin):
    """
    Summarize a scan at the Package levels. Mark summarized resources as "filtered".
    """
    sort_order = 10

    options = [
        CommandLineOption(('--package-summary',),
            is_flag=True, default=False,
            help='Summarize license and copyright at the package level. '
                 'Filter summarized files',
            help_group=POST_SCAN_GROUP)
    ]

    def is_enabled(self, package_summary, **kwargs):
        return package_summary

    def process_codebase(self, codebase, package_summary, with_files=False, **kwargs):
        # find which attributes are available for summarization by checking the root
        # resource
        root = codebase.root
        if not hasattr(root, 'packages'):
            if TRACE:
                logger_debug('PackageSummary: process_codebase: no packages')
            return

        # keep a set of resources that are part of packages and a set of resources
        # that are not part of packages
        packaged_resource_rids = set()
        free_resource_rids = set()

        for resource in codebase.walk(topdown=True):
            packages_info = resource.packages
            if not packages_info and resource.rid not in packaged_resource_rids:
                if TRACE:
                    logger_debug('PackageSummary: process_codebase: free resource', resource.path)

                free_resource_rids.add(resource.rid)
                continue

            if TRACE:
                logger_debug('PackageSummary: process_codebase: package resource', resource.path)

            # here we are at the root of a package.
            ###########################
            # FIXME: we DO NOT deal for now properly with multiple package at the same root!!!!
            # if len(packages_info) > 1:
            #     raise Exception('Cannot summarize a directory that contain multiple packages.')
            ###########################
            for package_info in packages_info:
                package_class = get_package_class(package_info)
                package_resources = list(package_class.get_package_resources(resource, codebase))
                if TRACE:
                    logger_debug('PackageSummary: process_codebase: summarizing resources', '\n'.join(r.path for r in package_resources))

                if not package_resources:
                    continue

                packaged_resource_rids.update(r.rid for r in package_resources)

                # set the files list optionally
                if with_files:
                    files = getattr(package_info, 'files', None)
                    if files is None:
                        package_info['files'] = files = []
                    files.extend(models.Resource(**r.to_dict(skinny=True))
                                 for r in package_resources)

                # collect and set licenses and copyrights of all package resources
                license_expressions = []
                package_license_expression = package_info.get('license_expression')
                if package_license_expression:
                    license_expressions.append(package_license_expression)

                copyrights = []
                package_copyright = package_info.get('copyright')
                if package_copyright:
                    copyrights.append(package_copyright)

                for packres in package_resources:
                    license_expressions.extend(getattr(packres, 'license_expressions', []))

                    coprs = (c['value'] for c in getattr(packres, 'copyrights', []))
                    copyrights.extend(coprs)

                license_expressions = combine_license_expressions(license_expressions, simplify=True)
                package_info['license_expression'] = license_expressions

                copyrights = '\n'.join(copyrights)
                package_info['copyright'] = copyrights

                if TRACE:
                    logger_debug('PackageSummary: process_codebase: summary: license', license_expressions, 'copyright:', copyrights)


            codebase.save_resource(resource)

        # also mark all the "packaged" resource as "filtered"
        for prid in packaged_resource_rids:
            pr = codebase.get_resource(prid)
            pr.is_filtered = True
            codebase.save_resource(pr)


# TODO: improve what is returned
def combine_license_expressions(expressions, simplify=False):
    """
    Return a license expression string combining multiple `expressions` with an
    AND.
    """
    expressions = [e for e in expressions if e and e.strip()]

    if len(expressions) == 1:
        return expressions[0]

    licensing = Licensing()
    # join the possible multiple detected license expression with an AND
    expression_objects = [licensing.parse(e, simple=True) for e in expressions]
    combined_expression_object = licensing.AND(*expression_objects)
    if simplify:
        combined_expression_object = combined_expression_object.simplify()
    return str(combined_expression_object)
