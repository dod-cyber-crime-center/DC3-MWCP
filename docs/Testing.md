# Testing Parsers

The DC3-MWCP framework produces JSON results for given samples
run against specified config parsers. Since the JSON output is already easily parseable,
the output of a parser itself can be used to represent both expected results and act as a test case.
By using JSON output that is known to be valid as a test case, the creation of test cases
becomes simplified and streamlined.

The `mwcp-test` command line utility has been created for users to generate and run test cases.

- [Executing Existing Test Cases](#executing-existing-test-cases)
- [Creating or Adding Test Cases](#creating-or-adding-test-cases)
    - [Determining files to use as test cases](#determining-file-to-use-as-test-cases)
    - [Adding test cases](#adding-test-cases)
- [Updating Test Cases](#updating-test-cases)
- [Removing Test Cases](#removing-test-cases)
- [Testing External Parsers](#testing-external-parsers)


## Executing Existing Test Cases

Possibly the most routine action is to execute existing test cases. This is performed with -t (a parser must be selected also).

```bash
$ mwcp-test -p foo -t

Running test cases. May take a while...
All Passed = True

```

`-a` can be used to validate all parsers instead of selecting an individual parser.

The `-k` and `-x` can be used to set which fields should be compared.
`-k` sets the list of fields to compare and `-x` is a list of the exclusions.
By default, debug field is excluded. These lists of fields should be provided as
comma separated lists of the field names (with no white space).

```bash
$ mwcp-test -p foo -t -v -k url,address

Running test cases. May take a while...
All Passed = True

$ mwcp-test -p foo -t -v -x debug,outputfile

Running test cases. May take a while...
All Passed = True

```


The following command line options can also be used to modify how the results are output to the console:
* `-f` : Display details only for failed test cases
* `-j` : JSON formatted output.
* `-s` : Silent. Only display a simple statement saying whether all test cases passed or not.

## Creating or Adding test cases

The basic steps in creating test cases are:
1. Identify list of files which serve as effective test cases
2. Add the test case files to the test cases
3. Validate that the test cases work


### Determining files to use as test cases

#### Basics

The first step in creating test cases is finding malware samples that:
* Have known attributes based on reverse engineering (e.g. callout domains, mutexes, etc...)
* Work with the relevant parser to produce these known attributes

#### Creating a list of files

Using the `mwcp-tool -i` option is a simple way to run a list of files against a parser in MWCP. The `-i` option expects an input text with one full absolute file path per line.

Example:

```
        C:\MalwareRepo\0cc1\0cc175b9c0f1b6a831c399e269772661
        C:\MalwareRepo\91eb\92eb5ffee6ae2fec3ad71c777531578f
        C:\MalwareRepo\4a8a\4a8a08f09d37b73795649038408b5f33
 ```


#### Generating and verifying results

Now that a valid input file has been created, the `mwcp-tool` script can be used along with the `-i` option and `-p` option to run a list of files against a given parser. The steps here are:
1. Run the list of files against an DC3-MWCP parser
2. Manually view the results produced by each file
3. Ensure each result is meaningful - parser worked properly, results show valuable configuration data, etc.
4. If appropriate, update the config parser so it works on files that it should and restart this verification process
5. Now, if any files are in the file list that produce no meaningful results, remove them from the list. If that was necessary, repeat these steps.

IMPORTANT: Regression tests are used to validate future config parser changes. Selectively creating test cases using appropriate samples is critical.

Usage:

```
mwcp-test -p <one parser name> -i <input file>
```

### Adding Test Cases

The default action of `mwcp-test` is to add (or replace) test cases, if input files are provided. Like `mwcp-tool`, the input files can be specified as the last arguments on the command line or the -i option can be used to specify a list of input file names.

``` bash
$ mwcp-test -p foo file1.exe file2.exe

Updating results for file1.exe in mwcp\parsertests\foo.json
Updating results for file2.exe in mwcp\parsertests\foo.json

$ echo file1.exe > inputs.txt
$ echo file2.exe >> inputs.txt
$ mwcp-test -p foo -i inputs.txt

Updating results for file1.exe in mwcp\parsertests\foo.json
Updating results for file2.exe in mwcp\parsertests\foo.json
```

## Updating Test Cases

When a parser is updated or any other situation requires all the existing test cases to be regenerated, the -u option should be used. It will simply re-run the metadata
extraction for all the input files in the current test cases and replace the results.

```bash
$ mwcp-test.py -p foo -u

Updating results for file1.exe in mwcp\parsertests\foo.json
Updating results for file2.exe in mwcp\parsertests\foo.json
Updating results for file3.exe in mwcp\parsertests\foo.json
```

## Removing Test Cases

Test cases can be removed using the -d option and specifying a list of file. As with addition, this can be a list of files on the command line or a file containing a list.


```
$ mwcp-test -p foo -d file1.exe file2.exe

Removing results for file1.exe in mwcp\parsertests\foo.json
Removing results for file2.exe in mwcp\parsertests\foo.json
```


## Testing External Parsers

By default, DC3-MWCP will only support running and updating tests that come with MWCP or have been
installed by a [parser package](ParserInstallation.md#formal-parser-packaging).
If you would like to use `mwcp-test` with your own external parsers you will need
to use the `--parserdir` and `--testcasedir` to tell MWCP where the parser and test cases reside.

```
mwcp-test --parserdir=C:\parsers --testcasedir=C:\parsertests -p foo -t
mwcp-test --parserdir=C:\parsers --testcasedir=C:\parsertests -p foo -u
```
