# Python Style Guide
Below are the guidelines. Keep in mind "a foolish consistency is the hobgoblin of little minds" - Ralph Waldo Emerson. If you've got a good reason to occasionally do something slightly different from these guidelines, we'll trust you to use your noggin. However, in the vast majority of circumstances, these guidelines should be followed. Note that these guidelines only apply to python 2.7 and will need updated if/when we move to a python 3 environment.

- [Formatting](#formatting)
- [Naming](#naming)
- [Commenting](#commenting)
- [Imports](#imports)
- [Misc](#misc)


## Formatting
- Do not use tab characters for indentation; use four spaces. Pretty much any non-notepad text editor can do this automatically when you press tab once configured correctly.
- The standard page width is 110 characters. Obviously, things like long YARA rules will violate this, and that's fine.
    - When splitting up a long line, do your best to align the wrapped text with the rest of its context.
        ```python
        outputs.append((output, sum(map(lambda c: c.encode('unicode-escape').startswith(('\\x', '\\u')), output)), code_page))

        # Becomes:

        outputs.append((output,
                        sum(map(lambda c: c.encode('unicode-escape').startswith(('\\x', '\\u')),
                                output)),
                        code_page))
        ```
    - For wrapping `if` statements, aligning the first wrapped line with the first term of the `if` statement will pretty much line up with the next line of code. Therefore, for the first wrapped line, add an additional four spaces.
        ```python
        if os.path.exists(local_path) and \
               hashlib.md5(open(local_path, 'rb').read()).hexdigest().upper() == idc.GetInputMD5():
            # ...

        # Rather than:

        if os.path.exists(local_path) and \
            hashlib.md5(open(local_path, 'rb').read()).hexdigest().upper() == idc.GetInputMD5():
            # ...
        ```
- Avoid nesting control flow and/or logic statements more than four layers deep.
- Assignments, arithmetics, and boolean operators should always be surrounded by one space on either side.
    - Do not attempt to line up multiple assignments on different lines.
- `,` should only be followed with a space. `:` should be followed by a blank space when used in defining a dictionary or lambda.
- Unary negation `-1` should only be preceded by a space.
- The following characters should NOT be surrounded by spaces: `{ } [ ] ( )`
- `self` and `cls` should always be the first parameter when they are present.
- Group like things together. I.E, group global definitions, then group classes, then group global functions and finally global instructions.
- There should be one blank line before function definitions.
- There should be two blank lines before class definitions.
- There should be two blank lines after the last line in a class
- There should be two blank lines after the document level multi-line comment.
- There should be two blank lines after the imports.
- There should be two blank lines after the group of global variable definitions.
- There should be two blank lines before any global functions when transitioning from classes
- The file should end with exactly one blank line.

## Naming
- Variables should be named in lowercase underscore case - super_special_function
- "Internal use" variables, functions, and classes should be prepended with an underscore - _internal_function
- To avoid conflicts with python keywords, use a trailing underscore - file_
- Starting and ending a name with `__` as that indicates a "magic" name. Only do this if you know how python will automatically use it (i.e. do not invent new magic names).
- Classes should be in title case - `EncodedString`
- Constants should be in uppercase. This should include the vast majority of global variables.
- Modules/packages should have short, lowercase names. Underscores can be used to separate words, but again, short is important.
    - Family names should retain their standard formatting.

## Commenting
- All docstrings must be wrapped with triple double quotes: `"""`
- All files should have a docstring at the top containing author and a brief description.
- All functions and classes should have a docstring in reStructuredText format documenting the parameters, attributes, return values and exceptions it raises.
    - Please use typing when you can.
    - Docstrings need to explain the function/class to a degree that, if someone else imported it, they would know how to use the function/class correctly.
    - Docstrings should be correctly formatted so it can be interpreted by IDE's like PyCharm.
    ```python
    def convert_foos_to_bars(foos):
        """
        Converts foos to bars.

        :param list[Foo] foos: A list of valid foos that will be converted to bars.

        :returns: The list of bars.
        :rtype: list[Bar]

        :raises FooBar: If a foo is invalid and cannot be converted to a bar.
        """
    ```
- Particularly convoluted, clever, or generally unusual sections of code require a comment before the relevant code. For these comments, use the single line comment `#` and as many lines as necessary to explain what's going on.
- Comments need to be aligned with their context. Since the comments occur before their context, they should be aligned with the next line of code.

## Imports
- Modules should be imported with the `import foo` or `from foo import bar` syntax.
- Imports should be grouped according to these guidelines:
    - First anything imported from regular python (e.g. os, itertools), sorted alphabetically.
    - Next any third party libraries, sorted alphabetically.
    - Last should be any imports from the project itself, sorted alphabetically.

```python
import os
import sys

import pefile
from oletools import oleobj

from mwcp import Reporter, Parser
```

## Misc
- Use `thing is not None` rather than `thing != None`
- Put any negations on a particular boolean operation in the operation, not before it.
    - `len(string) <= length` rather than `not len(string) > length`
    - `size != length` rather than `not size == length`
    - `thing is not None` rather than `not thing is None`
- When in an elif chain with multiple variables, put the variables in the same order when they are used again.
    ```python
    if flags & 0x4 and len(string) > 25: ...
    elif len(string) == 10 and verbose: ...
    elif flags == 0 and len(string) < 4 and verbose: ...
    ```
- Avoid `return` or `return None` as the last instruction. Python functions automatically return None when they reach their end. Note that if you're in a loop, this does not apply.
- Prefer `{} [] ()` to `dict() list() and tuple()`
- Avoid `except:` where possible. It is significantly safer to list the expected exception(s) when you know what they are likely to be (e.g. `except AttributeError as e:` `except (TypeError, RuntimeError) as e:`).
- Always use the `with open(<filename>, <mode>) as f:` syntax. This will save you from forgetting to close your file handle.
- Avoid using/importing the "string" module. I.e. do `name.rstrip('\x00')` rather than `import string` `name = string.rstrip(name, '\x00')`
- All assignments should be on their own line. That means `start, index = 0` is bad.
    - Tuple expansion assignments must be on the same line: `name, size = obj.get_info()`
- Avoid catching exceptions that you can't handle. If an exception can occur because there is a bug in your code or a new sample is breaking your parser, let the exception get raised! The framework will handle catching and reporting the error for you.
    - A parser should raise an exception on new unexpected samples. This will help to quickly expose why and where the parser is failing. Making it easier to update and fix, with less manual debugging.
