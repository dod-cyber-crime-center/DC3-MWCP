# Parser Development

The high level steps for parser development are:

- Create new *_malwareconfigparser module
- Subclass `mwcp.Parser`
- Implement run()
- Use reporter object
  - Access malware sample
  - Report metadata
  - etc.

`foo_malwareconfigparser.py` is provided as an example and may be used as a template:


```python
import os
from mwcp import Parser

class Foo(Parser):
    def __init__(self, reporter = None):
        malwareconfigparser.__init__(self,
            description = 'example parser that works on any file',
            author = 'DC3',
            reporter = reporter
            )

    def run(self):

        #standardized metadata
        self.reporter.add_metadata("url", "http://127.0.0.1")

        #demonstrate access to sample
        self.reporter.debug("size of inputfile is %i bytes" % (len(self.reporter.data)))

        #other, non-standardized metadata
        #also demonstrate use of pefile object
        if self.reporter.pe:
            self.reporter.add_metadata("other", {"section0": self.reporter.pe.sections[0].Name.rstrip('\x00')})

        #demonstrate file output
        self.reporter.output_file("hello world", "fooconfigtest.txt", "example output file")

        #demonstrate use of filename()
        self.reporter.debug("operating on inputfile %s" % self.reporter.filename())

        #demonstrate use of managed tempdir
        with open(os.path.join(self.reporter.managed_tempdir(), "footmp.txt"), "w") as f:
            f.write("This is a temp file created in a directory that will be managed by the mwcp framework. \
                The directory will initially be empty, so there is no worry about name collisions. \
                The directory is deleted after this module run ends, unless tempcleanup is disabled.")

```

## Dispatching Component parsers
The above example works for simple cases. However, when you run into malware containing multiple components
embedded within each other with multiple variations, it can easily grow your parser to an unmanageable size.

MWCP comes with a Dispatcher model that allows you to organize your code based on their individual components
and variations.

For documentation please read: [Dispatcher Parser Development](DispatcherParserDevelopment.md).


## Parser Development Tips
- Standardized field mapping:
  - Let data type dictate field selection
  - Use most complete field possible
- Include additional context using other fields
- Output files/artifacts if they are relevant
- Let DC3-MWCP manage your temp files: see reporter.managed_tempdir()
- Stay portable:
  - Respect interfaces
  - Use common modules for dependencies
  - Maintain cross platform functionality: *nix and windows
- Do not use parser arguments unless absolutely necessary
- Use [mwcp.utils.construct](construct.ipynb) to help organize your config structures.

## Tech Anarchy Bridge

While DC3-MWCP does not include any malware parsers, it does include a bridge to enable use
of the parsers provided by Kev of techanarchy.net/malwareconfig.com. The purpose
of this bridge is to execute the Tech Anarchy parsers, capture the output, and normalize
the fields. This bridge can be used to create simple DC3-MWCP modules which call the underlying
Tech Anarchy parsers. It is the responsibility of the user to ensure that field mappings are
correct, adjusting the bridge as necessary.

See mwcp/resources/techanarchy_bridge.py