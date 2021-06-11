"""
This is a small helper script for converting legacy parser tests using the flat
metadata schema into the newer schema.
"""

import logging
import os
import pathlib
import sys

import click

import mwcp
from mwcp.tester import Tester  # old interface
from mwcp import testing        # new interface


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("-d", "--debug", is_flag=True, help="Enables DEBUG level logs.")
@click.option("-v", "--verbose", is_flag=True, help="Enables INFO level logs.")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    help="File path to configuration file.",
    default=mwcp.config.user_path,
    show_default=True,
    envvar="MWCP_CONFIG",
    show_envvar=True,
)
@click.option(
    "--parser-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Optional extra parser directory.",
)
@click.option(
    "--parser-config",
    type=click.Path(exists=True, dir_okay=False),
    help="Optional parser configuration file to use with extra parser directory.",
)
@click.option(
    "--parser-source",
    help="Set a default parsers source to use. If not provided parsers from all sources will be available.",
)
@click.option(
    "-t",
    "--testcase-dir",
    type=click.Path(file_okay=False),
    help="Directory containing JSON test case files. (defaults to a "
    '"tests" directory located within the parsers directory)',
)
@click.option(
    "-m",
    "--malware-repo",
    type=click.Path(file_okay=False),
    help="Directory containing malware samples used for testing.",
)
@click.option(
    "--force", is_flag=True,
    help="Force test case creation even when errors are encountered."
)
@click.option(
    "--update-existing", is_flag=True,
    help="Whether to update already converted tests cases.",
)
@click.option(
    "--continue-on-failure", is_flag=True,
    help="Whether to continue updating test cases if a legacy test case fails."
)
@click.option(
    "--remove-old", is_flag=True,
    help="Remove old test cases as new ones are created."
)
@click.option(
    "--skip-testing", is_flag=True,
    help="Don't run original test cases before updating."
)
@click.argument("parser", required=False)
def main(debug, verbose, config_path, parser_dir, parser_config, parser_source,
         testcase_dir, malware_repo, force, update_existing,
         continue_on_failure, remove_old, skip_testing, parser):
    # region Initial Setup stolen from cli

    # Setup configuration
    mwcp.config.load(config_path)
    if parser_dir:
        mwcp.config["PARSER_DIR"] = parser_dir
    parser_dir = mwcp.config.get("PARSER_DIR")
    if parser_config:
        mwcp.config["PARSER_CONFIG_PATH"] = parser_config
    parser_config = mwcp.config.get("PARSER_CONFIG_PATH")
    if parser_source:
        mwcp.config["PARSER_SOURCE"] = parser_source
    parser_source = mwcp.config.get("PARSER_SOURCE")

    # Setup logging
    mwcp.setup_logging()
    if debug:
        logging.root.setLevel(logging.DEBUG)
    elif verbose:
        logging.root.setLevel(logging.INFO)
    # else let log_config.yaml set log level.

    # Register parsers
    mwcp.register_entry_points()
    if parser_dir:
        mwcp.register_parser_directory(parser_dir, config_file_path=parser_config)
    if parser_source:
        mwcp.set_default_source(parser_source)

    # endregion

    # Overwrite configuration with command line flags.
    if testcase_dir:
        mwcp.config["TESTCASE_DIR"] = testcase_dir
    if malware_repo:
        mwcp.config["MALWARE_REPO"] = malware_repo

    existing_test_cases = list(testing.iter_test_cases())

    skipped = []
    tester = Tester(parser_names=[parser or None])
    for legacy_test_case in tester.test_cases:
        input_file_path = legacy_test_case.input_file_path
        parser = legacy_test_case.parser
        md5 = pathlib.Path(input_file_path).name
        friendly_name = f"{parser}-{md5}"

        # First see if testcase was already added.
        found = False
        for test_case in existing_test_cases:
            if input_file_path.endswith(test_case.md5) and parser in test_case.name:
                found = True
                break
        if found and not update_existing:
            click.secho(f"[+] Test case for {friendly_name} already exists. Skipping...")
            continue

        click.secho(f"[+] Converting {friendly_name}")

        # Test if legacy test case works.
        if not skip_testing:
            results = legacy_test_case.run()
            if not results.passed:
                results.print()
                if continue_on_failure:
                    click.secho(f"[!] Failed above test. Skipping...", fg="red")
                    skipped.append(friendly_name)
                    continue
                else:
                    click.secho(f"[!] Failed above test. Exiting...", fg="red")
                    sys.exit(1)

        # Create new test case.
        success = testing.add_tests(
            input_file_path,
            parsers=[parser],
            force=force,
            update=update_existing,
        )
        if not success:
            if continue_on_failure:
                click.secho(f"[!] Failed to add test case {friendly_name}. Skipping...", fg="red")
                skipped.append(friendly_name)
                continue
            else:
                click.secho(f"[!] Failed to add test case {friendly_name}. Exiting...", fg="red")
                sys.exit(1)

        # Remove old test case.
        # TODO: implement to remove test for specific testcase... or just not support this.
        if remove_old:
            results_file_path = tester.get_results_filepath(parser)
            results_list = tester.read_results_file(results_file_path)
            for index, file_path in enumerate(tester._list_test_files(results_list)):
                if os.path.basename(file_path) == os.path.basename(input_file_path):
                    break
            else:
                click.secho(f"Failed to remove legacy test case for {friendly_name}", fg="red")
                continue
            del results_list[index]
            if not results_list:
                pathlib.Path(results_file_path).unlink()
            else:
                tester.write_results_file(results_list, results_file_path)

    # Show user what test cases we skipped.
    if skipped:
        skipped_str = "\n\t- ".join(skipped)
        click.secho(
            f"The following test cases were not converted due to failure: \n\t- {skipped_str}",
            fg="red"
        )
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
