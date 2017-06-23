#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="mwcp",
    version="1.0.0",
    author="DC3",
    description="DC3-MWCP: A framework malware configuration parsers. The main focus is standardizing malware parsers and their output.",
    license="MIT",
    keywords="malware",
    url="http://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/",
    packages=find_packages(),
    package_data={
        '': ['*.txt', '*.json', 'resources/*.txt', 'resources/*.json']
    },
    scripts=["mwcp-tool.py", "mwcp-client.py",
             "mwcp-server.py", "mwcp-test.py"],
)
