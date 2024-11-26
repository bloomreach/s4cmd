#!/usr/bin/env python

#
# Copyright 2012-2018 BloomReach, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Super S3 command line tool, setup.py
"""

import os, stat
from setuptools import setup, find_packages
from setuptools.command.install import install as _install

__author__ = "Chou-han Yang"
__copyright__ = "Copyright 2012-2018 BloomReach, Inc."
__license__ = "Apache License 2.0"
__version__ = "2.1.0"
__maintainer__ = "Navin Pai, Naveen Vardhi"
__status__ = "Development"

this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md')) as f:
  long_description = f.read()

class install(_install):
  def run(self):
    _install.run(self)
    
setup(name='s4cmd',
      version=__version__,
      description='Super S3 command line tool',
      author=__author__,
      license=__license__,
      license_files  = ["LICENSE"],
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/bloomreach/s4cmd',
      py_modules=['s4cmd'],
      scripts=['s4cmd.py'], # Added s4cmd.py as script for backward compatibility
      install_requires=['boto3>=1.3.1', 'pytz>=2016.4'],
      entry_points={
        'console_scripts': [
            's4cmd = s4cmd:main',
        ]},
      cmdclass={'install': install},
      classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
      ],
    )
