"""
Tests the CLI tools.
"""

import hashlib
import json
import os
import re
import sys

import pytest
import pathlib

import mwcp
from mwcp import cli



def test_parse(tmpdir, script_runner):
    """Test running a parser"""
    test_file = tmpdir / 'test.txt'
    test_file.write_binary(b'This is some test data!')
    test_file = test_file.basename
    cwd = str(tmpdir)

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
[+] operating on inputfile {0}

----Output Files----

fooconfigtest.txt    example output file
                     5eb63bbbe01eeed093cb22bb8f5acdc3

'''.format(test_file)

    # Check that the output file was created
    output_file = os.path.join(cwd, '{}_mwcp_output'.format(test_file), '5eb63_fooconfigtest.txt')
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


def test_get_malware_repo_path(tmpdir):
    """Tests generating malware repo path."""
    malware_repo = tmpdir.mkdir('malware_repo')
    test_file = tmpdir / 'test.txt'
    test_file.write_binary(b'This is some test data!')

    mwcp.config['MALWARE_REPO'] = str(malware_repo)
    sample_path = cli._get_malware_repo_path(str(test_file))
    assert sample_path == str(malware_repo / 'fb84' / 'fb843efb2ffec987db12e72ca75c9ea2')


def test_add_to_malware_repo(tmpdir):
    """Tests adding a file to the malware repo."""
    malware_repo = tmpdir.mkdir('malware_repo')
    test_file = tmpdir / 'test.txt'
    test_file.write_binary(b'This is some test data!')

    mwcp.config['MALWARE_REPO'] = str(malware_repo)
    sample_path = cli._add_to_malware_repo(str(test_file))
    expected_sample_path = malware_repo / 'fb84' / 'fb843efb2ffec987db12e72ca75c9ea2'
    assert sample_path == str(expected_sample_path)
    assert expected_sample_path.exists()
    assert expected_sample_path.read_binary() == test_file.read_binary()


def test_list(tmpdir, script_runner, Sample_parser):
    """
    Tests displaying a list of parsers.

    (This is also where we test the parser registration flags.)
    """
    # First ensure our foo parser is registered via entry_points.
    ret = script_runner.run('mwcp', 'list', '--json')
    # print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    results = json.loads(ret.stdout, encoding='utf8')
    assert len(results) > 1
    for name, source_name, author, description in results:
        if name == u'foo':
            assert source_name == u'mwcp'
            assert author == u'DC3'
            assert description == u'example parser that works on any file'
            break
    else:
        pytest.fail('Sample parser was not listed.')

    parser_file, config_file = Sample_parser
    parser_dir = parser_file.dirname

    # Now try adding a the Sample parser using the --parser-dir flag.
    ret = script_runner.run(
        'mwcp',
        '--parser-dir', str(parser_dir),
        '--parser-config', str(config_file),
        'list', '--json'
    )
    # print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    results = json.loads(ret.stdout, encoding='utf8')
    assert len(results) > 1
    for name, source_name, author, description in results:
        if source_name == str(parser_dir):
            assert name == u'Sample'
            assert author == u'Mr. Tester'
            assert description == u'A test parser'
            break
    else:
        pytest.fail('Sample parser from parser directory was not listed.')

    # If we set --parser-source we should only get our registered parser from the directory.
    ret = script_runner.run(
        'mwcp',
        '--parser-dir', str(parser_dir),
        '--parser-config', str(config_file),
        '--parser-source', str(parser_dir),
        'list', '--json'
    )
    # print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    results = json.loads(ret.stdout, encoding='utf8')
    assert results == [
        [u'Sample', str(parser_dir), u'Mr. Tester', u'A test parser']
    ]

    # Now try adding the config_file path to the __init__.py file in order to avoid having
    # to manually use the --parser-config flag.
    init_file = pathlib.Path(parser_dir) / '__init__.py'
    init_file.write_text(u'config = {!r}'.format(str(config_file)), 'utf8')
    ret = script_runner.run(
        'mwcp',
        '--parser-dir', str(parser_dir),
        '--parser-source', str(parser_dir),
        'list', '--json'
    )
    # print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    results = json.loads(ret.stdout, encoding='utf8')
    assert results == [
        [u'Sample', str(parser_dir), u'Mr. Tester', u'A test parser']
    ]


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
    csv_file = tmpdir / 'test.csv'

    cli._write_csv(input_files, results, str(csv_file))

    expected = (
        'scan_date,inputfilename,outputfile.name,outputfile.description,outputfile.md5,a,address,other.field1,other.field2\n'
        '[TIMESTAMP],file1.exe,"out_name\nout_name2","out_desc\nout_desc2","out_md5\nout_md52",,"https://google.com\nftp://amazon.com",value1,"value2\nvalue3"\n'
        '[TIMESTAMP],file2.exe,,,,"b\nc",,,\n'
    )
    with csv_file.open() as fo:
        # Replace timestamp.
        results = re.sub('\n[^"]*?,', '\n[TIMESTAMP],', fo.read())
        assert results == expected


def test_csv_cli(tmpdir, script_runner):
    """Tests the csv feature on the command line."""
    test_file = tmpdir / 'test.txt'
    test_file.write_binary(b'This is some test data!')
    test_file = test_file.basename
    cwd = str(tmpdir)

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
    
    
def test_add_testcase(tmpdir, script_runner):
    """Tests adding a parser testcase."""
    malware_repo = tmpdir.mkdir('malware_repo')
    test_case_dir = tmpdir.mkdir('testcases')
    test_file = tmpdir / 'test.txt'
    test_file.write_binary(b'This is some test data!')

    # Add a test case for our foo parser.
    ret = script_runner.run(
        'mwcp', 'test', 'foo',
        '--testcase-dir', str(test_case_dir),
        '--malware-repo', str(malware_repo),
        '--add', str(test_file),
    )
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    # Ensure test file got placed in the right location.
    test_sample = malware_repo / 'fb84' / 'fb843efb2ffec987db12e72ca75c9ea2'
    assert test_sample.exists()
    assert test_sample.read_binary() == test_file.read_binary()

    # Ensure the test case was created correctly.
    test_case_file = test_case_dir / 'foo.json'
    assert test_case_file.exists()
    expected_results = [
        {
            u"debug": [
                u"[+] File {} identified as Foo.".format(test_sample.basename),
                u"[+] size of inputfile is 23 bytes",
                u"[+] operating on inputfile {}".format(test_sample.basename)
            ],
            u"url": [
                u"http://127.0.0.1"
            ],
            u"outputfile": [
                [
                    u"fooconfigtest.txt",
                    u"example output file",
                    u"5eb63bbbe01eeed093cb22bb8f5acdc3"
                ]
            ],
            u'inputfilename': u'{MALWARE_REPO}\\fb84\\fb843efb2ffec987db12e72ca75c9ea2',
            u"address": [
                u"127.0.0.1"
            ]
        }
    ]
    assert json.loads(test_case_file.read_text('utf8')) == expected_results

    # Now test that it ignores a second add of the same file.
    ret = script_runner.run(
        'mwcp', 'test', 'foo',
        '--testcase-dir', str(test_case_dir),
        '--malware-repo', str(malware_repo),
        '--add', str(test_file)
    )
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    assert ret.stderr.splitlines()[-1] == (
        '[-] (MainProcess:mwcp.tester): Test case for {test_sample} already exists in {test_case_file}'
    ).format(test_sample=str(test_sample), test_case_file=str(test_case_file))
    assert json.loads(test_case_file.read_text('utf8')) == expected_results

    # Now test force updating the results.
    ret = script_runner.run(
        'mwcp', 'test', 'foo',
        '--testcase-dir', str(test_case_dir),
        '--malware-repo', str(malware_repo),
        '--update',
        '--add', str(test_file)
    )
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    # Since it would be too hard to dynamically change what the parser does, just ensure
    # we get the right stderr and the testcase hasn't changed.
    assert ret.stderr.splitlines()[-1] == (
        '[+] (MainProcess:mwcp.tester): Updating results for {test_sample} in {test_case_file}'
    ).format(test_sample=str(test_sample), test_case_file=str(test_case_file))
    assert json.loads(test_case_file.read_text('utf8')) == expected_results


    # Now test the deletion of the test case.
    ret = script_runner.run(
        'mwcp', 'test', 'foo',
        '--testcase-dir', str(test_case_dir),
        '--malware-repo', str(malware_repo),
        '--delete', str(test_file)
    )
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    # Make sure we did NOT remove the file from the malware repo.
    assert test_sample.exists()
    assert test_sample.read_binary() == test_file.read_binary()

    # Check that the test case has been removed, but the test case file still exists.
    assert test_case_file.exists()
    assert json.loads(test_case_file.read_text('utf8')) == []


def test_add_filelist_testcase(tmpdir, script_runner):
    """Tests bulk adding testcases with --add-filelist flag."""
    malware_repo = tmpdir.mkdir('malware_repo')
    test_case_dir = tmpdir.mkdir('testcases')

    # Create a file list of paths.
    filelist = []
    for i in range(10):
        file = tmpdir / 'file_{}'.format(i)
        data = 'this is file {}'.format(i).encode('utf8')
        file.write_binary(data)
        filelist.append((str(file), hashlib.md5(data).hexdigest()))

    filelist_txt = tmpdir / 'filelist.txt'
    filelist_txt.write_text(u'\n'.join(file_path for file_path, _ in filelist), 'utf8')

    # Add a test case for our sample parser.
    ret = script_runner.run(
        'mwcp', 'test', 'foo',
        '--testcase-dir', str(test_case_dir),
        '--malware-repo', str(malware_repo),
        '--add-filelist', str(filelist_txt),
    )
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    # Ensure a sample was added for each file and exists in the testcase.
    test_case_file = test_case_dir / 'Foo.json'
    assert test_case_file.exists()
    testcases = json.loads(test_case_file.read_text('utf8'))
    input_files = [testcase[u'inputfilename'] for testcase in testcases]
    assert len(input_files) == len(filelist)
    for _, md5 in filelist:
        test_sample = malware_repo / md5[:4] / md5
        assert test_sample.exists()
        assert hashlib.md5(test_sample.read_binary()).hexdigest() == md5
        assert '{{MALWARE_REPO}}\\{}\\{}'.format(md5[:4], md5) in input_files
