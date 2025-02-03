#!/usr/bin/env python
"""
A framework for malware configuration parsers.
"""

from setuptools import setup, find_namespace_packages

setup(
    name="mwcp",
    author="DC3",
    author_email="dc3.tsd@us.af.mil",
    keywords="malware",
    url="https://github.com/dod-cyber-crime-center/DC3-MWCP/",
    packages=find_namespace_packages(),
    include_package_data=True,
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    python_requires=">=3.9",
    entry_points={
        'console_scripts': [
            'mwcp = mwcp.cli:main',
            'poshdeob = mwcp.utils.poshdeob:main',
            'mwcp_update_legacy_tests = mwcp.tools.update_legacy_tests:main',
        ],
        'mwcp.parsers': [
            'dc3 = mwcp.parsers',
        ]
    },
    install_requires=[
        'anytree',
        'appdirs',
        'attrs>=20.3.0',
        'bitarray',
        'cattrs',
        'click>=8.0.1',
        'construct >=2.9.45, <2.11',
        'defusedxml',
        'future',
        'isodate',
        'jinja2',  # For construct.html_hex()
        'jsonschema_extractor>=1.0',
        'lief>=0.16.0;python_version>="3.9"',
        'packaging',
        'pandas',
        'pefile>=2019.4.18',
        'pyasn1',
        'pyasn1_modules',
        'pyelftools',
        'pyparsing',
        'pytest>=6.0.0',
        'pytest-datadir',
        'pytest-xdist',
        'pytest-mock',
        'pytest-cov',
        'pyyaml',
        'requests',
        'ruamel.yaml',
        'six',
        'tabulate[widechars]<1.0.0',
        'stix2',
        'yara-python',
        # For the server and API
        'flask',
        'pygments',

        # Dependencies for builtin parsers.
        'pycdlib',
        'pycryptodome',
        'olefile',
    ],
    extras_require={
        'dragodis': ['dragodis>=0.2.0'],
        'kordesii': ['kordesii>=2.0.0'],
        'testing': [
            'jsonschema',
            'dragodis',
            'rugosa',
        ],
    }
)
