# Testing Parsers

The DC3-MWCP framework produces JSON results for given samples
run against specified config parsers. Since the JSON output is already easily parseable,
the output of a parser itself can be used to represent both expected results and act as a test case.
By using JSON output that is known to be valid as a test case, the creation of test cases
becomes simplified and streamlined.

The `mwcp test` command line utility has been created for users to generate and run test cases.

- [Executing Existing Test Cases](#executing-existing-test-cases)
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


## Executing Existing Test Cases

Possibly the most routine action is to execute existing test cases.

```console
> mwcp test foo

Running test cases. May take a while...
All Passed = True
```

If a parser is not provided all registered parsers will be tested.

```console
> mwcp test

PARSER argument not provided. Run tests for ALL parsers? [Y/n]:
Running tests cases. May take a while...
```

Please see `mwcp test -h` to view all options.

The following command line options can also be used to modify how the results are output to the console:
* `-f / --show-passed` : Display details only for failed test cases
* `-s / --silent` : Silent. Only display a simple statement saying whether all test cases passed or not.

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

