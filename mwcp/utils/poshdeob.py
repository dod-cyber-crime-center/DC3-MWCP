r"""
poshdeob - Powershell Deobfuscator

This utility is used for converting obfuscated code and pulling strings along the way.

WARNING: This is a very rudimentary parser that doesn't support a lot of things.
 It makes no promises in deobfuscating all your code.

Usage:
    from mwcp.utils import poshdeob

    deobfuscated_code, found_strings = poshdeob.debofuscate(obfuscated_code)
"""

import argparse
from typing import Tuple, List

import pyparsing as pp
import re
import sys


_PARSER = None


# region PARSING HOOKS


# Some variables found to be used in obfuscated code with the most probable values.
# TODO: Fill this up!
_VARIABLE_LOOKUP = {
    "pshome": r"C:\Windows\System32\WindowsPowerShell\v1.0",
    "shellid": "Microsoft.PowerShell",
    "env:public": r"C:\Users\Public",
    "env:comspec": r"C:\Windows\system32\cmd.exe",
    "verbosepreference.tostring()": "SilentlyContinue",
}


def _indexing(tokens):
    indices = tokens.indices
    if len(indices) == 1:
        return tokens.data[int(indices[0])]
    else:
        return [tokens.data[int(i)] for i in indices]


def _string_format(tokens):
    format_string = tokens.format_string
    for format in tokens.format:
        format_string = format_string.format(*format.params)
    return format_string


def _string_replace(tokens):
    data = tokens.data
    for replace in tokens.replace:
        # Only escape "\" otherwise regex complains if it trailing.
        old = replace.old.replace("\\", "\\\\")
        new = replace.new.replace("\\", "\\\\")
        data = re.sub(old, new, data, flags=re.IGNORECASE if replace.command != "creplace" else 0)
    return data


def _split(tokens):
    split_data = [tokens.data]
    for split in tokens.split:
        for delimiter in split.delimiters:
            new_split_data = []
            for data in split_data:
                new_split_data.extend(re.split(delimiter, data))
            split_data = new_split_data
    return split_data


# endregion


# region PARSING GRAMMER


def OptionalParen(expr, parenthesis="()"):
    """
    Wraps pyparsing expression to add optional parenthesis.

    >>> hello = OptionalParen(pp.Literal('hello'))
    >>> hello.parseString('hello')
    (['hello'], {})
    >>> hello.parseString('((hello))')
    (['hello'], {})
    >>> goodbye = OptionalParen(pp.Literal('goodbye'), parenthesis='{}')
    >>> goodbye.parseString('goodbye')
    (['goodbye'], {})
    >>> goodbye.parseString('{goodbye}')
    (['goodbye'], {})
    """
    lpar, rpar = map(pp.Suppress, parenthesis)
    term = pp.Forward()
    term <<= expr | (lpar + term + rpar)
    return term


def _gen_parser():
    r"""
    Generates PyParsing grammar for parsing common powershell operations.

    Tests:
    >>> parser = _gen_parser()
    >>> parser.parseString("'{1} {0}'-f 'world','hello'")
    (['hello world'], {})
    >>> parser.parseString('''
    ...     'fGshellolNRfGs'-rEplaCE  ((([cHaR]108+[cHaR]78+[cHaR]82))),'!' .rePLace('fGs',[cHaR]96)''')
    (['`hello!`'], {})
    >>> parser.parseString("'ATBZCFD'-spLIT 'Z'-SPLIT'T'  -spLiT 'F'")
    (['A', 'B', 'C', 'D'], {})
    >>> parser.parseString("$ENv:PuBlIc[13]")
    (['i'], {})
    >>> parser.parseString("('h', 'e', 'l', 'lo')-JOIn ''")
    (['hello'], {})
    >>> parser.parseString("'he`llo'")
    (['hello'], {})
    >>> parser.parseString("'FOtestingFO'.RePLaCE('FO','`')")
    (['`testing`'], {})
    """
    char = ("[" + pp.CaselessKeyword("char") + "]" + pp.Word(pp.nums)("num")).setParseAction(lambda t: chr(int(t.num)))
    string = (
        (pp.Suppress("'") + "`" + pp.Suppress("'"))
        | (pp.Suppress('"') + "`" + pp.Suppress('"'))
        | pp.QuotedString("'", escChar="`", escQuote="''", multiline=True, convertWhitespaceEscapes=False)
        | pp.QuotedString('"', escChar="`", escQuote='""', multiline=True, convertWhitespaceEscapes=False)
    )
    variable = ("$" + pp.oneOf(_VARIABLE_LOOKUP.keys(), caseless=True)("var")).setParseAction(
        lambda t: _VARIABLE_LOOKUP[t.var.lower()]
    )

    _string = pp.Suppress(pp.Optional("[" + pp.CaselessKeyword("string") + "]")) + OptionalParen(
        pp.Suppress(pp.Optional("[" + pp.CaselessKeyword("string") + "]")) + string | char | variable
    )
    concat_string = OptionalParen(
        pp.delimitedList(OptionalParen(_string), delim="+").setParseAction(lambda t: "".join(t))
    )

    # TODO: Support ranges and other fancy indexing.
    indexing = (concat_string("data") + "[" + pp.delimitedList(pp.Word(pp.nums))("indices") + "]").setParseAction(
        _indexing
    )

    # Combine used to enforce there is no space between "c" and "replace"
    _replace_command = pp.Combine(pp.Optional(pp.CaselessLiteral("c")) + pp.CaselessLiteral("replace"))("command")
    string_replace = (
        concat_string("data")
        + pp.OneOrMore(
            pp.Group(
                (pp.Combine("-" + _replace_command) + concat_string("old") + "," + concat_string("new"))
                | (
                    "."
                    + ("'" + _replace_command + "'" | '"' + _replace_command + '"' | _replace_command)
                    + ("(" + concat_string("old") + "," + concat_string("new") + ")")
                )
            )
        )("replace")
    ).setParseAction(_string_replace)

    string_format = (
        concat_string("format_string")
        + pp.OneOrMore(pp.Group(pp.CaselessKeyword("-f") + pp.delimitedList(concat_string)("params")))("format")
    ).setParseAction(_string_format)

    split = (
        concat_string("data")
        + pp.OneOrMore(
            pp.Group(
                (pp.CaselessKeyword("-split") + concat_string("delimiters"))
                | ("." + pp.CaselessKeyword("split") + "(" + concat_string("delimiters") + ")")
            )
        )("split")
    ).setParseAction(_split)

    join = (
        OptionalParen(pp.delimitedList(concat_string)("string_list"))
        + pp.CaselessKeyword("-join")
        + concat_string("join_string")
    ).setParseAction(lambda t: t.join_string.join(t.string_list))

    join_unary = (
        (pp.CaselessKeyword("-join") | pp.CaselessKeyword("[string]::join"))
        + "("
        + OptionalParen(pp.delimitedList(concat_string)("string_list"))
        + ")"
    ).setParseAction(lambda t: "".join(t.string_list))

    # fmt: off
    poss_elements = OptionalParen(
        string_format
        | string_replace
        | split
        | join_unary
        | join
        | indexing
        | concat_string
    )
    # fmt: on

    return poss_elements


# endregion


def _format_code_string(string):
    """Formats string into user readable string that can be placed into powershell code."""
    # Use least used quotes for best readability.
    if string.count("'") > string.count('"'):
        code_string = '"' + string.replace('"', '""') + '"'
    else:
        code_string = "'" + string.replace("'", "''") + "'"
    return code_string


def deobfuscate(code, depth=32, recursive=False) -> Tuple[str, List[str]]:
    """
    Deobfuscates strings found in powershell code.

    :param code: obfuscated powershell code
    :param depth: Number of levels of deobfuscation to run. (defaults to 32)
    :param recursive: Whether to recursively deobfuscate found strings.
                      (be careful, this can be very slow!!)

    returns: tuple containing -- (deobfuscate code, list of strings found)
    """
    if depth <= 0:
        raise ValueError("Depth must be a positive number.")
    orig_depth = depth

    if isinstance(code, bytes):
        code = code.decode("latin1")

    # Generate parser on first run.
    global _PARSER
    if not _PARSER:
        _PARSER = _gen_parser()
        _PARSER.keepTabs = True  # start/end offsets get screwy if we don't enable this.

    # Continuously run code through string deobfuscation until we don't get anything new.
    # (This is necessary because pyparsing is not a true recursive descent parser)
    prev_code = ""
    strings = []
    while depth and prev_code != code:
        depth -= 1
        prev_code = code
        strings = []
        code_replacements = []
        for result, start, end in _PARSER.scanString(code):
            if recursive:
                new_result = []
                for string in result:
                    deob_code, sub_strings = deobfuscate(string, depth=orig_depth, recursive=True)
                    new_result.append(deob_code)
                    strings.extend(sub_strings or [deob_code])
                result = new_result
            else:
                strings.extend(result)

            # replace obfuscated code with less obfuscated code.
            code_string = ", ".join(map(_format_code_string, result))
            # Only wrap parenthesis if more than one string.
            if len(result) > 1:
                code_string = "({})".format(code_string)

            code_replacements.append((start, end, code_string))

        # Replace code with new code.
        new_code = ""
        index = 0
        for start, end, code_string in code_replacements:
            # Sometimes pyparsing includes whitespace at the end of the parsed string for some reason...
            try:
                while code[end - 1] in ("\r", "\n", " "):
                    end -= 1
            except IndexError:
                pass
            new_code += code[index:start] + code_string
            index = end
        new_code += code[index:]
        code = new_code

    return code, strings


def main():
    """CLI interface"""
    arg_parser = argparse.ArgumentParser("Powershell Deobfuscator")
    arg_parser.add_argument("INPUT", help="Input file (or code) to deobfuscate")
    arg_parser.add_argument("OUTPUT", nargs="?", help="Deobfuscated file (default: stdout)")

    args = arg_parser.parse_args()

    if args.OUTPUT:
        output = open(args.OUTPUT, "w")
    else:
        output = sys.stdout

    try:
        with open(args.INPUT, "r") as fo:
            deob_code, _ = deobfuscate(fo.read())
            output.write(deob_code)
    finally:
        if args.OUTPUT:
            output.close()


if __name__ == "__main__":
    main()
