import os
import sys
import subprocess
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from pathlib import Path

class CMakeExtension(Extension):
    def __init__(self, name, sourcedir=''):
        Extension.__init__(self, name, sources=[])
        self.sourcedir = os.path.abspath(sourcedir)

class BuildCMakeExt(build_ext):
    def run(self):
        print(self.extensions)
        for ext in self.extensions:
            self.build_extension(ext)

    def build_extension(self, ext) -> None:
        try:
            subprocess.check_output(['cmake', '--version'])

        except OSError:
            raise RuntimeError('CMake is not installed.')

setup(
    name='neuralpy',
    version='0.1',
    description='My PyBind module',
    long_description='',
    author='Linus Henke',
    author_email='linus.henke@mci.edu',
    ext_modules=[CMakeExtension('neuralpy', sourcedir="neuralpy")],
    cmdclass={'build_ext': BuildCMakeExt},
    zip_safe=False,
    python_requires=">=3.7"
)
