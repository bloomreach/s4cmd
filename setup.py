#!/usr/bin/env python

#
# Copyright 2012 BloomReach, Inc.
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
__copyright__ = "Copyright 2014 BloomReach, Inc."
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__version__ = "2.0.0"
__maintainer__ = __author__
__status__ = "Development"

def _post_install():
  os.chmod("/etc/bash_completion.d/s4cmd",755)

class install(_install):
  def run(self):
    _install.run(self)
    mode = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IROTH
    os.chmod("/etc/bash_completion.d/s4cmd", mode)
    

setup(name='s4cmd',
      version=__version__,
      description='Super S3 command line tool',
      author=__author__,
      license=__license__,
      url='https://github.com/bloomreach/s4cmd',
      py_modules=['s4cmd'],
      scripts=['s4cmd', 's4cmd.py'], # Added s4cmd.py as script for backward compatibility
      install_requires=['boto3>=1.3.1'],
      data_files=[('/etc/bash_completion.d/',['data/bash-completion/s4cmd'])],
      cmdclass={'install': install},
    )
