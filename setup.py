#!/usr/bin/env python
"""
A framework for malware configuration parsers.
"""

from setuptools import setup, find_packages

setup(
    name="mwcp",
    author="DC3",
    author_email="dcci@dc3.mil",
    keywords="malware",
    url="http://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/",
    packages=find_packages(),
    include_package_data=True,
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
    ],
    entry_points={
        'console_scripts': [
            'mwcp = mwcp.cli:main',
            'poshdeob = mwcp.utils.poshdeob:main',
            'mwcp_update_legacy_tests = mwcp.tools.update_legacy_tests:main',
        ],
        'mwcp.parsers': [
            'mwcp = mwcp.parsers',
        ]
    },
    install_requires=[
        'anytree',
        'appdirs',
        'attrs>=20.3.0',
        'cattrs',
        'click>=8.0.1',
        'construct==2.9.45',  # pin because parsers are very dependent on this.
        'future',
        'jinja2',  # For construct.html_hex()
        'jsonschema_extractor==0.9',
        'pandas',
        'pefile>=2019.4.18',
        'pyelftools',
        'pyparsing',
        'pytest>=6.0.0',
        'pytest-datadir',
        'pytest-xdist',
        'pyyaml',
        'requests',
        'ruamel.yaml',
        'six',
        'tabulate[widechars]<1.0.0',

        # For the server and API
        'flask',
        'pygments',
    ],
    extras_require={
        'kordesii': ['kordesii>=2.0.0'],
        'testing': [
            'jsonschema',
        ],
    }
)
