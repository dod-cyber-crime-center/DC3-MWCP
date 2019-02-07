"""
Tests the CLI tools.
"""

from __future__ import unicode_literals, print_function

from future.builtins import open

import json
import re
import os
import sys

import pytest

from mwcp import cli


def test_testcases(tmpdir, script_runner):
    """Run mwcp test on all test cases."""
    # Change working directory so we can cleanup outputted files.
    cwd = str(tmpdir)

    # Run all parser tests.
    ret = script_runner.run('mwcp', 'test', '-y', cwd=cwd)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success


def test_parse(tmpdir, script_runner, test_file):
    """Test running a parser"""
    # Change working directory so we can cleanup outputted files.
    cwd = str(tmpdir)
    test_file = os.path.basename(test_file)

    # Run the foo parser on the test input file.
    ret = script_runner.run('mwcp', 'parse', 'foo', test_file, cwd=cwd)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    assert ret.stdout == \
'''
----Standard Metadata----

url                  http://127.0.0.1
address              127.0.0.1

----Debug----

[+] File test.txt identified as Foo.
[+] size of inputfile is 23 bytes
[+] Output file: fooconfigtest.txt
[+] operating on inputfile {}

----Output Files----

fooconfigtest.txt    example output file
                     5eb63bbbe01eeed093cb22bb8f5acdc3

'''.format(test_file)

    # Test the "-i" flag.
    ret = script_runner.run('mwcp', 'parse', '-i', 'foo', test_file, cwd=cwd)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    assert ret.stdout == \
'''
----File Information----

inputfilename        {0}
md5                  fb843efb2ffec987db12e72ca75c9ea2
sha1                 5e90c4c2be31a7a0be133b3dbb4846b0434bc2ab
sha256               fe5af8c641835c24f3bbc237a659814b96ed64d2898fae4cb3d2c0ac5161f5e9

----Standard Metadata----

url                  http://127.0.0.1
address              127.0.0.1

----Debug----

[+] File test.txt identified as Foo.
[+] size of inputfile is 23 bytes
[+] Output file: fooconfigtest.txt
[+] operating on inputfile {0}

----Output Files----

fooconfigtest.txt    example output file
                     5eb63bbbe01eeed093cb22bb8f5acdc3

'''.format(test_file)

    # Check that the output file was created
    output_file = os.path.join(cwd, 'fooconfigtest.txt')
    assert os.path.isfile(output_file)

    # Test the "--no-output-files" flag.
    os.unlink(output_file)
    assert not os.path.isfile(output_file)
    ret = script_runner.run('mwcp', 'parse', '--no-output-files', 'foo', test_file, cwd=cwd)
    assert ret.success
    # We should still not have the output file
    assert not os.path.isfile(output_file)

    # Test the json formating
    ret = script_runner.run('mwcp', 'parse', '-f', 'json', 'foo', test_file, cwd=cwd)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    assert json.loads(ret.stdout) == [
        {
            "debug": [
                "[+] File {} identified as Foo.".format(test_file),
                "[+] size of inputfile is 23 bytes",
                "[+] Output file: fooconfigtest.txt",
                "[+] operating on inputfile {}".format(test_file)
            ],
            "url": [
                "http://127.0.0.1"
            ],
            "outputfile": [
                [
                    "fooconfigtest.txt",
                    "example output file",
                    "5eb63bbbe01eeed093cb22bb8f5acdc3"
                ]
            ],
            "address": [
                "127.0.0.1"
            ]
        }
    ]



def test_list_parsers(script_runner):
    """Tests the list parser feature."""
    # Test text out
    ret = script_runner.run('mwcp', 'list')
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    assert ret.stdout
    assert "bar" in ret.stdout
    assert "foo" in ret.stdout

    # Test json out
    ret = script_runner.run('mwcp', 'list', '-j')
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    output = json.loads(ret.stdout)
    assert output == [
        ['bar', 'mwcp', 'DC3', 'example parser that uses dispatcher components'],
        ['foo', 'mwcp', 'DC3', 'example parser that works on any file']
    ]


# REMOVED: Deprecated feature.
# def test_list_fields(script_runner):
#     """Test the list fields features."""
#     # Test text out
#     ret = script_runner.run('mwcp-tool', '--fields')
#     print(ret.stdout)
#     print(ret.stderr, file=sys.stderr)
#     assert ret.success
#     assert ret.stdout
#     assert "address" in ret.stdout
#
#     # Test json out
#     ret = script_runner.run('mwcp-tool', '--fields', '--json')
#     print(ret.stdout)
#     print(ret.stderr, file=sys.stderr)
#     assert ret.success
#     output = json.loads(ret.stdout)
#     assert output
#     assert len(output) == 48
#     assert "address" in output
#     assert output["address"]["type"] == "listofstrings"


# REMOVED: Deprecated feature.
# def test_get_file_paths(tmpdir):
#     """Tests the _get_file_paths in mwcp-tool"""
#     # tests that it finds valid file paths.
#     assert tool._get_file_paths([tool.__file__], is_filelist=False) == [tool.__file__]
#
#     # Test file list indirection
#     file_list = os.path.join(str(tmpdir), 'file_list.txt')
#     with open(file_list, 'w') as f:
#         f.write('file1.exe\n')
#         f.write('file2.exe')
#
#     assert tool._get_file_paths([file_list], is_filelist=True) == ['file1.exe', 'file2.exe']
#
#     sys.stdin = io.StringIO('file3.exe\nfile4.exe')
#     assert tool._get_file_paths(["-"], is_filelist=True) == ['file3.exe', 'file4.exe']


def test_csv(tmpdir):
    """Tests the csv feature."""
    input_files = ['file1.exe', 'file2.exe']
    results = [
        {
            'other': {'field1': 'value1', 'field2': ['value2', 'value3']},
            'outputfile': [['out_name', 'out_desc', 'out_md5'], ['out_name2', 'out_desc2', 'out_md52']],
            'address': ['https://google.com', 'ftp://amazon.com']
        },
        {
            'a': ['b', 'c'],
        }
    ]
    csv_path = os.path.join(str(tmpdir), 'test.csv')

    cli._write_csv(input_files, results, csv_path)

    expected = (
        'scan_date,inputfilename,outputfile.name,outputfile.description,outputfile.md5,a,address,other.field1,other.field2\n'
        '[TIMESTAMP],file1.exe,"out_name\nout_name2","out_desc\nout_desc2","out_md5\nout_md52",,"https://google.com\nftp://amazon.com",value1,"value2\nvalue3"\n'
        '[TIMESTAMP],file2.exe,,,,"b\nc",,,\n'
    )
    with open(csv_path, 'r') as fo:
        # Replace timestamp.
        results = re.sub('\n[^"]*?,', '\n[TIMESTAMP],', fo.read())
        assert results == expected


def test_csv_cli(tmpdir, script_runner, test_file):
    """Tests the csv feature on the command line."""
    cwd = str(tmpdir)
    test_file = os.path.basename(test_file)
    ret = script_runner.run('mwcp', 'parse', '--no-output-files', '--format', 'csv', 'foo', test_file, cwd=cwd)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)

    assert ret.success

    expected = (
        'scan_date,inputfilename,outputfile.name,outputfile.description,outputfile.md5,address,debug,url\n'
        '[TIMESTAMP],{0},fooconfigtest.txt,example output file,5eb63bbbe01eeed093cb22bb8f5acdc3,127.0.0.1,'
        '"[+] File test.txt identified as Foo.\n'
        '[+] size of inputfile is 23 bytes\n'
        '[+] operating on inputfile {0}'
        '",http://127.0.0.1\n'.format(test_file)
    )
    results = ret.stdout
    # Replace timestamp.
    results = re.sub('\n[^"]*?,', '\n[TIMESTAMP],', results)
    assert results == expected