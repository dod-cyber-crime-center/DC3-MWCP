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
            'poshdeob = mwcp.utils.poshdeob:main'
        ],
        'mwcp.parsers': [
            'mwcp = mwcp.parsers',
        ]
    },
    install_requires=[
        'appdirs',
        'click',
        'construct==2.9.45',  # pin because parsers are very dependent on this.
        'future',
        'jinja2',  # For construct.html_hex()
        'pefile>=2019.4.18',
        'pyelftools',
        'pyparsing==2.3.0',  # 2.4.0 seems to break poshdeob
        'pyyaml',
        'requests',
        'ruamel.yaml',
        'six',
        'tabulate',

        # For the server and API
        'flask~=1.1.0',
        'pygments~=2.2.0',

        # Testing
        'pytest',
        'pytest-console-scripts',
        'tox',
    ],
    extras_require={
        'kordesii': ['kordesii>=2.0.0'],
    }
)
