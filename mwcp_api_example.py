#!/usr/bin/env python
"""
Simple example to demonstrate use of the API provided by DC3-MWCP framework.
"""

# first, import mwcp
import mwcp

# create an instance of the Reporter class
reporter = mwcp.Reporter()
"""
The Reporter object is the primary DC3-MWCP framework object, containing most input and output data
and controlling execution of the parser modules.

The most common parameters to provide are parserdir and resourcedir, depending upon your installation.
"""
# view location of resource and parser directories
print(reporter.parserdir)

# view available parsers
print(mwcp.get_parser_descriptions())

# run the dummy config parser, view the output
reporter.run_parser("foo", "README.md")

# alternate, run on provided buffer:
reporter.run_parser("foo", data=b"lorem ipsum")

print(reporter.pprint(reporter.metadata))

# access output files
for filename in reporter.outputfiles:
    print("%s: %i bytes" % (reporter.outputfiles[filename]['path'],
                            len(reporter.outputfiles[filename]['data'])))
