""" setup.py
REPOSITORY:
  https://github.com/DavidJLambert/Two-Windows-Event-Log-Summarizers

SUMMARY:
  Scans XML exports of the Windows Event Log and reports summary statistics.

AUTHOR:
  David J. Lambert

VERSION:
  0.1.0

DATE:
  May 31, 2019
"""

from distutils.core import setup

with open("README.rst", 'r') as f:
    long_description = f.read()

setup(
    author='David J. Lambert',
    author_email='David5Lambert7@gmail.com',
    description='Two Windows Event Log Summarizers',
    license='MIT License',
    long_description=long_description,
    long_description_content_type='text/x-rst',
    name='Two Windows Event Log Summarizers',
    platforms=["Windows"],
    py_modules=["read_registry_direct","read_xml_export"],
    url='https://github.com/DavidJLambert/Two-Windows-Event-Log-Summarizers',
    version='0.1.0',
    install_requires=[
          'frozendict',
          'PyWin32',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: System :: Logging',
        'Topic :: System :: Systems Administration',
    ],
)
