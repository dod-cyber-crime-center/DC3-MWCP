"""Tests for found bugs/issues."""

from __future__ import print_function

import six

import csv
import sys
import io


def test_csv_row_bug(script_runner, tmpdir, test_dir):
    """
    Tests bug where first row is formatted different from other rows.
    Occurs when outputting csv and input file is a directory.
    """
    ret = script_runner.run(
        'mwcp', 'parse', 'foo', '--format', 'csv', str(test_dir / '*')
    )
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    if six.PY2:
        reader = csv.reader(io.BytesIO(ret.stdout))
    else:
        reader = csv.reader(io.StringIO(ret.stdout))
    rows = list(reader)
    assert len(rows) == len(test_dir.listdir()) + 1
    assert rows[0] == ['scan_date', 'inputfilename', 'outputfile.name',
                       'outputfile.description', 'outputfile.md5', 'address', 'debug', 'url']
    for i, row in enumerate(rows[1:]):
        assert row[0] and row[1]
        # Test entries except the timestamp and full file path.
        assert row[2:] == [
            'fooconfigtest.txt',
            'example output file',
            '5eb63bbbe01eeed093cb22bb8f5acdc3',
            '127.0.0.1',
            ('[+] File test_{0}.txt identified as Foo.\n'
            '[+] size of inputfile is 23 bytes\n'
            '[+] operating on inputfile test_{0}.txt').format(i),
            'http://127.0.0.1',
        ]
