# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-

from setuptools import setup, find_packages
import pip
import manifesttool
import os

install_reqs = pip.req.parse_requirements('requirements.txt', session=pip.download.PipSession())
reqs = [str(r.req) for r in install_reqs]

if os.name == 'nt':
    entry_points={
        "console_scripts": [
            "manifest-tool=manifesttool.clidriver:main",
        ],
    }
    scripts = []
else:
    platform_deps = []
    # entry points are nice, but add ~100ms to startup time with all the
    # pkg_resources infrastructure, so we use scripts= instead on unix-y
    # platforms:
    scripts = ['bin/manifest-tool', ]
    entry_points = {}

setup(
    name='manifest-tool',
    version=manifesttool.__version__,
    description='Tool/lib to create and parse manifests',
    long_description=open("README.md").read(),
    url='https://github.com/ARMmbed/update-client-manifest-manager/manifestTool',
    author='Brendan Moran',
    author_email='brendan.moran@arm.com',
    packages=find_packages(exclude=['tests*']),
    zip_safe=False,
    scripts=scripts,
    entry_points=entry_points,
    install_requires=reqs
)
