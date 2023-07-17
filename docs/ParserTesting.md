# Testing Parsers

The DC3-MWCP framework produces JSON results for given samples
run against specified config parsers. Since the JSON output is already easily parseable,
the output of a parser itself can be used to represent both expected results and act as a test case.
By using JSON output that is known to be valid as a test case, the creation of test cases
becomes simplified and streamlined.

The `mwcp test` command line utility has been created for users to generate and run test cases.

- [Updating Legacy Test Cases](#updating-legacy-test-cases)
- [Executing Existing Test Cases (legacy)](#executing-existing-test-cases-legacy)
- [Executing Existing Test Cases](#executing-existing-test-cases)
- [Downloading Test Samples](#downloading-test-samples)
- [Creating or Adding Test Cases](#creating-or-adding-test-cases)
    - [Determining files to use as test cases](#determining-file-to-use-as-test-cases)
- [Adding test cases](#adding-test-cases)
- [Updating Test Cases](#updating-test-cases)
- [Removing Test Cases](#removing-test-cases)
- [Testing External Parsers](#testing-external-parsers)


### Guides
- [Parser Development](ParserDevelopment.md)
- [Parser Components](ParserComponents.md)
- [Parser Installation](ParserInstallation.md)
- [Parser Testing](ParserTesting.md)
- [Python Style Guide](PythonStyleGuide.md)


## Updating Legacy Test Cases

As of version 3.3.0, MWCP has updated how it presents its metadata schema. Henceforth, the format of the
reported json has changed, breaking existing test cases. 
This has been set as the default for the `test` command. To run legacy test cases, ensure you include the
`--legacy` flag.

A small command line tool `mwcp_update_legacy_tests` has been created to ease in this transition.

To update your tests run the following command:

```console
> mwcp_update_legacy_tests
```

This will create test cases for all installed parsers using the new schema.
New tests cases are split into subdirectories by parser with each input file having its own json file.
These tests will be located in the same location as the old test cases.

If you also want the old tests removed, completely replacing the test cases, include the flag `--remove-old`.

By default, the script will first run the legacy test cases to ensure they pass
before creating the new test cases. This is to ensure your system is creating correct test cases. 
This can be skipped using the flag `--skip-testing`.
*NOTE: Tests run in this script isn't multiprocessed like usual, so it may be beneficial
to run `mwcp test` separately and then enable this flag.*

If a legacy test case fails, the whole script will halt unless the `--continue-on-failure` flag is set.
In which case, the test case will simply be skipped.


If the results file for a new test case already exists, the script will not recreate the test case unless the `--update-existing` flag is set.


To convert only a specific parser, provide the name of the parser in the command line:

```console
> mwcp_update_legacy_tests SuperMalware
```


## Executing Existing Test Cases (legacy)

To run the legacy testing utility (not backed by pytest), ensure you include the `--legacy` flag.

```console
> mwcp test foo --legacy

Running test cases. May take a while...
All Passed = True
```

If a parser is not provided all registered parsers will be tested.

```console
> mwcp test --legacy

PARSER argument not provided. Run tests for ALL parsers? [Y/n]:
Running tests cases. May take a while...
```

Please see `mwcp test -h` to view all options.

The following command line options can also be used to modify how the results are output to the console:
* `-f / --show-passed` : Display details only for failed test cases
* `-s / --silent` : Silent. Only display a simple statement saying whether all test cases passed or not.


## Executing Existing Test Cases

DC3-MWCP runs the parser tests using [pytest](https://pytest.org) as the backend for testing the newer
metadata schema introduced in version 3.3.0.

When you run `mwcp test`, a call to pytest will be run, testing all or a specific query of parsers.

```console
> mwcp test
> mwcp test SuperMalware
```

Since the newer testing utility is backed by pytest, testing is not limited to specific parsers.
We can now use any valid expression that can be used with the `-k` pytest flag.

For example, to test a specific input file we can provide the all or part of the md5.

```console
> mwcp test abd3
```

Or test parsers from a specific parser source.
```console
> mwcp test acme
```

Or we can even get fancy with exclusionary rules.
```console
> mwcp test "SuperMalware and not abd3"
```


As well, pytest can be used directly to handle more advanced configuration.

Use the `parsers` marker to only test parsers and not framework code. Or vise versa.

```console
> pytest --pyargs mwcp -m parsers
> pytest --pyargs mwcp -m "not parsers"
```

The `--malware-repo` and `--testcase-dir` options can also be used directly with pytest.

```console
> pytest --pyargs mwcp -m parsers --malware-repo="C:/malware" --testcase-dir="C:/mwcp_parser_tests" 
```

Finally, if you would like to see what pytest command would be run for a given `mwcp test` command,
we can use the `-c`/`--command` flag.
This will not run any tests, but rather just output the `pytest` command.

```console
> mwcp test foo --command
pytest 'C:\Python310\Lib\site-packages\mwcp\tests\test_parsers.py' --disable-pytest-warnings --durations 10 -vv -k foo -n auto
```

## Code Coverage

The `--cov` flag can be used to enable code coverage tracking through the use of the [pytest-cov](https://github.com/pytest-dev/pytest-cov) plugin. 
Only the files which contain the `Parser` component classes for the requested parser(s) will be included in the code coverage.

After testing, the [Coverage.py](https://coverage.readthedocs.io) tool can be used to generate reports.


```console
> mwcp test foo --cov
> coverage html
> open htmlcov/index.html
```


## Downloading Test Samples

Use the `mwcp download` command to download a sample from the malware repo into the current directory.
This command can take either a full/partial md5, a parser name, or previously failed test samples.

### Downloading MD5 hashes

```
> mwcp download d41d8cd98f00b204e9800998ecf8427e
> mwcp download d41d8
```


### Downloading Parser samples

```
> mwcp download SuperMalware 
```


### Downloading failed test samples.

```
> mwcp download --last-failed
```


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


#### Generating and verifying results

Using wild cards is a simple way to run a directory of files against a parser in DC3-MWCP.

For example:
```console
> mwcp parse foo ./malwarez/**/*
```

Once run, manually view the results produced by each file. Ensure each result is meaningful - 
parser worked properly, results show valuable configuration data, etc.

If appropriate, update the config parser so it works on files that it should and restart this verifcation process.

IMPORTANT: Regression tests are used to validate future config parser changes. 
Selectively creating test cases using appropriate samples is critical.


## Adding Test Cases

`mwcp test` with the `--add` flag can be used to add new test case files.

```console
> mwcp test foo --add=file1.exe --add=file2.exe

Updating results for file1.exe in mwcp\parsers\tests\foo.json
Updating results for file2.exe in mwcp\parsers\tests\foo.json
```

## Updating Test Cases

When a parser is updated or any other situation requires all the existing test cases to be regenerated, 
the `--update` option should be used. It will simply re-run the metadata
extraction for all the input files in the current test cases and replace the results.

```console
> mwcp test foo --update

Updating results for file1.exe in mwcp\parsers\tests\foo.json
Updating results for file2.exe in mwcp\parsers\tests\foo.json
Updating results for file3.exe in mwcp\parsers\tests\foo.json
```

## Removing Test Cases

Test cases can be removed using the `--delete` option and specifying the path to a test file.

```console
> mwcp test foo --delete=file1.exe --delete=file2.exe

Removing results for file1.exe in mwcp\parsers\tests\foo.json
Removing results for file2.exe in mwcp\parsers\tests\foo.json
```


## Testing External Parsers

By default, DC3-MWCP will only support running and updating tests that come with MWCP or have been
installed by a [parser package](ParserInstallation.md#formal-parser-packaging).
If you would like to use `mwcp test` with your own external parsers you will need
to use the `--parser-dir` and `--testcase-dir` to tell MWCP where the parser and test cases reside.

```console
> mwcp --parser-dir=C:\parsers test --testcase-dir=C:\parsers\tests foo
> mwcp --parser-dir=C:\parsers test --testcase-dir=C:\parsers\tests foo -u
```

## Using a Malware Repository

If desired, all test files can be automatically added to an external malware repository 
which is a separate directory that organizes the samples by md5.

To use, add `--malware-repo` pointing to your repository when adding or deleting tests:

```console
> mwcp test --malware-repo=X:\MalwareRepo foo -a ./malware.bin
> mwcp test --malware-repo=X:\MalwareRepo foo -x ./malware.bin
```

This will cause the input file to be copied into the malware repository
and the input file path within the test case will be appended with `{MALWARE_REPO}`.
This allows for more portable test case files and prevents exposing internal file paths.


For more persistence, you can add the malware repository path to the configuration parameter `MALWARE_REPO`.
(Run `mwcp config`). This will cause `--malware-repo` to automatically apply if not supplied. 

