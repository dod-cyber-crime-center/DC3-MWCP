"""
Interface for Runner class.
"""
import contextlib
import json
import logging
import pathlib
import shutil
import tempfile
import warnings
from typing import Union, Type

import mwcp
from mwcp.report import Report
from mwcp import config, Parser

logger = logging.getLogger(__name__)


class OutputLogger:
    """
    Redirects stdout to the logger.
    """

    def __init__(self):
        # noinspection PyTypeChecker
        self._redirector = contextlib.redirect_stdout(self)

    def __enter__(self):
        self._redirector.__enter__()
        return self

    def __exit__(self, *args):
        self._redirector.__exit__(*args)

    def write(self, message):
        logger.info(message)

    def flush(self):
        pass


class Runner:
    """
    Controller for running a parser on a given input file.
    Its main purpose is to house the run() function for running a parser and producing
    a Report object.
    """

    def __init__(
        self, *,
        output_directory: Union[str, pathlib.Path] = None,
        temp_directory: Union[str, pathlib.Path] = None,
        cleanup_temp_files: bool = False,
        include_file_data: bool = False,
        prefix_output_files: bool = True,
        include_logs: bool = True,
        log_level: int = None,
        log_filter: logging.Filter = None,
    ):
        """
        Initializes the Reporter object

        :param temp_directory: Path to temporary directory to use for storing temporarily
            files. By default, a temporary directory created by the OS will be used.
            This can be useful to set if you plan to also disable cleanup of temp files.
        :param output_directory:
            sets directory for output_file(). Should not be written to (or read from) by parsers
            directly (use tempdir)
            If not provided, files will not be written out.
        :param cleanup_temp_files: Whether to cleanup (deletion) of temporary files.
        :param include_file_data: Whether to include file data in the generated report.
            If disabled, only the file path, description, and md5 will be included.
        :param prefix_output_files: Whether to include a prefix of the first 5 characters
            of the md5 on output files. This is to help avoid overwriting multiple
            output files with the same name.
        :param include_logs: Whether to include error and debug logs in the generated report.
        :param log_level: If including logs, the logging level to be collected.
            (Defaults to currently set effective log level)
        :param log_filter: If including logs, this can be used to pass in a custom filter for the logs.
            Should be a valid argument for logging.Handler.addFilter()
        """

        # defaults
        if temp_directory:
            self.tempdir = pathlib.Path(temp_directory)
        else:
            # TODO: Fix this.
            self.tempdir = pathlib.Path(tempfile.gettempdir())

        self._managed_tempdir = None
        self._output_dir = pathlib.Path(output_directory) if output_directory else None

        # These are the arguments that we will pass to each Report construction.
        self._report_config = {
            "include_logs": include_logs,
            "include_file_data": include_file_data,
            "prefix_output_files": prefix_output_files,
            "output_directory": self._output_dir,  # TODO: does runner still need output_dir?
            "log_level": log_level,
            "log_filter": log_filter,
        }

        self._cleanup_temp_files = cleanup_temp_files

        # TODO: Usage of fields is deprecated. Remove this in a future version.
        with open(config.get("FIELDS_PATH"), "rb") as f:
            self._fields = json.load(f)

        # This holds the last generated Report object from run_parser().
        # TODO: This is here to help keep backwards compatibility with attributes like self.metadata.
        #    This should be removed when we remove those attributes.
        self._report = None

    @property
    def metadata(self):
        warnings.warn(
            "Usage of the metadata attribute is deprecated. "
            "Please use the Report object returned by run() instead.",
            DeprecationWarning
        )
        # TODO: convert Report object into metadata object.
        if not self._report:
            return {}
        return self._report.metadata

    def add_metadata(self, *args, **kwargs):
        warnings.warn(
            ".add_metadata() is deprecated in favor of using .add() directly on the Report object.",
            DeprecationWarning
        )
        if not self._report:
            # This shouldn't occur unless the legacy Reporter was being used inappropriately.
            raise ValueError("add_metadata() cannot be called unless currently running a parser.")
        self._report.add_metadata(*args, **kwargs)

    def output_file(self, *args, **kwargs):
        warnings.warn(
            ".output_file() is deprecated in favor of adding a ResidualFile metadata element to Report.add()",
            DeprecationWarning
        )
        if not self._report:
            raise ValueError("output_file() cannot be called unless currently running a parser.")
        self._report.output_file(*args, **kwargs)

    @property
    def fields(self):
        warnings.warn(
            "Usage of the fields attribute is deprecated. ",
            DeprecationWarning
        )
        return self._fields

    @property
    def input_file(self):
        warnings.warn(
            "Usage of the input_file is deprecated. "
            "Please use the input_file attribute in the generated Report object instead.",
            DeprecationWarning
        )
        return self._report and self._report.input_file

    @property
    def managed_tempdir(self):
        """
        Returns the filename of a managed temporary directory. This directory will be deleted when
        parser is finished, unless tempcleanup is disabled.
        """
        warnings.warn(
            "managed_tempdir is deprecated. Please use FileObject.temp_path() instead.",
            DeprecationWarning
        )
        if not self._managed_tempdir:
            self._managed_tempdir = tempfile.mkdtemp(dir=self.tempdir, prefix="mwcp-managed_tempdir-")

            if self._cleanup_temp_files:
                logger.debug("Using managed temp dir: {}".format(self._managed_tempdir))

        return self._managed_tempdir

    @property
    def errors(self):
        warnings.warn(
            "errors is deprecated. Please access errors from mwcp.Report instead.",
            DeprecationWarning
        )
        return self._report.errors

    def run_parser(self, name, file_path=None, data=b""):
        warnings.warn(
            "run_parser() has been renamed to run()",
            DeprecationWarning
        )
        return self.run(name, file_path=file_path, data=data)

    def run(
            self,
            parser: Union[str, Type[Parser]],
            file_path: str = None,
            data: bytes = None,
    ) -> Report:
        """
        Runs specified parser on file

        :param parser: name or class of parser to run
        :param file_path: file to parse
        :param data: use data as file instead of loading data from filename

        :returns: mwcp.Report object containing parse results.
        """
        self._managed_tempdir = None

        if file_path:
            input_file = mwcp.FileObject.from_path(file_path, output_file=False)
        elif data is not None:
            input_file = mwcp.FileObject(data, output_file=False)
        else:
            raise ValueError("Either a file_path or data must be provided.")

        if isinstance(parser, str):
            parser_name = parser
            parser = None
        else:
            parser_name = parser.__name__

        report = Report(input_file=input_file, parser=parser_name, **self._report_config)
        # Need to keep a copy of the report here for backwards compatibility.
        # TODO: Remove this on a major release.
        self._report = report

        # We also have to include the report in the input_file incase the parser tries to dereference
        # reporter.
        # TODO: Remove this on a major release.
        input_file._report = report

        # Bit of a hack to get managed_tempdir and fields to be available to the parser from Report.
        # TODO: Remove this when we remove managed_tempdir.
        report.__class__.managed_tempdir = property(lambda _: self.managed_tempdir)
        report.__class__.fields = property(lambda _: self.fields)

        with report, OutputLogger():
            try:
                found = False
                # Parser was directly provided.
                if parser:
                    try:
                        parser.parse(input_file, report)
                    except (Exception, SystemExit):
                        logger.exception(
                            f"Error running parser {parser_name} on {file_path or input_file.md5}"
                        )

                # Parser name was provided, iterate through registered parsers.
                else:
                    for source, parser in mwcp.iter_parsers(parser_name):
                        found = True
                        try:
                            parser.parse(input_file, report)
                        except (Exception, SystemExit):
                            logger.exception(
                                f"Error running parser {source.name}:{parser.name} on {file_path or input_file.md5}"
                            )

                    if not found:
                        logger.error("Could not find parsers with name: {}".format(parser_name))

                return report

            finally:
                self.__cleanup()

    def print_report(self):
        """
        Output in human readable report format
        """
        warnings.warn(
            "print_report() is deprecated. Please use as_text() on the returned Report object instead.",
            DeprecationWarning
        )
        print(self._report.as_text())

    def get_output_text(self):
        """
        Get data in human readable report format.
        """
        warnings.warn(
            "get_output_text() is deprecated, please use as_text() on the returned Report object.",
            DeprecationWarning
        )
        return self._report.as_text()

    # TODO: Remove when we remote support for managed_tempdir.
    def __cleanup(self):
        """
        Cleanup things
        """
        # Cleanup temporary files created by FileObject.
        for file_object in mwcp.FileObject._instances:
            file_object._cleanup()
        mwcp.FileObject._instances = []

        # Delete temporary directory.
        if self._cleanup_temp_files and self._managed_tempdir:
            try:
                shutil.rmtree(self._managed_tempdir, ignore_errors=True)
            except Exception as e:
                logger.error("Failed to purge temp dir: %s, %s" % (self._managed_tempdir, str(e)))
        self._managed_tempdir = None

    def __del__(self):
        self.__cleanup()
