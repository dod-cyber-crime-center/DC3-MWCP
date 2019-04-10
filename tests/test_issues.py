"""Tests for found bugs/issues."""

from __future__ import print_function

import csv
import os
import sys


def test_csv_row_bug(script_runner, tmpdir, test_dir):
    """
    Tests bug where first row is formatted different from other rows.
    Occurs when outputting csv and input file is a directory.
    """
    csv_file = tmpdir / 'csv_file.csv'

    ret = script_runner.run(
        'mwcp-tool', '-p', 'foo', '-c', str(csv_file), str(test_dir), cwd=str(tmpdir))
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    assert csv_file.exists()

    with csv_file.open('r') as fo:
        reader = csv.reader(fo)
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
