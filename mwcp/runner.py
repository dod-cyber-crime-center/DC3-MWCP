"""
Interface for Runner class.
"""
from __future__ import annotations
import contextlib
import logging
import pathlib
from typing import TYPE_CHECKING, Union, Type, Tuple, Iterable

import yara

import mwcp
from mwcp.file_object import FileObject
from mwcp.report import Report
from mwcp.registry import iter_parsers
from mwcp.dispatcher import UnidentifiedFile

if TYPE_CHECKING:
    from mwcp import Parser, Dispatcher
    Parser = Union[Type[Parser], Dispatcher]

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
    Basic Runner which runs a given parser on a given file path.
    """

    def __init__(self, **report_config):
        # These are the arguments that we will pass to each Report construction.
        self._report_config = report_config

    def _parse(self, input_file: FileObject, parsers: Iterable[Parser], report: Report):
        for parser in parsers:
            logger.debug(f"Parsing {input_file.name} with {parser.name}")
            try:
                parser.parse(input_file, report)
            except (Exception, SystemExit):
                file_path = input_file.file_path if input_file._exists else input_file.md5
                logger.exception(
                    f"Error running parser {parser.name} on {file_path}"
                )

    def _generate_input_file(self, file_path: Union[str, pathlib.Path] = None, data: bytes = None) -> FileObject:
        if file_path:
            return FileObject.from_path(file_path, output_file=False)
        elif data is not None:
            return FileObject(data, output_file=False)
        else:
            raise ValueError("Either a file_path or data must be provided.")

    def run(
            self,
            parser: Union[str, Parser],
            file_path: Union[str, pathlib.Path] = None,
            data: bytes = None,
    ) -> Report:
        """
        Runs specified parser on file

        :param parser: name or class of parser to run
        :param file_path: file to parse
        :param data: use data as file instead of loading data from filename

        :returns: Report object containing parse results.
        """
        input_file = self._generate_input_file(file_path, data)

        if isinstance(parser, str):
            parser_name = parser
            parsers = [parser for _, parser in iter_parsers(parser_name)]
        else:
            parser_name = parser.name
            parsers = [parser]

        report = Report(input_file=input_file, parser=parser_name, **self._report_config)

        # We also have to include the report in the input_file incase the parser tries to dereference
        # reporter.
        # TODO: Remove this on a major release.
        input_file._report = report

        with report, OutputLogger():
            try:
                self._parse(input_file, parsers, report)
                return report
            finally:
                self._cleanup()

    def _cleanup(self):
        """
        Cleanup things
        """
        # Cleanup temporary files created by FileObject.
        for file_object in FileObject._instances:
            file_object._cleanup()
        FileObject._instances = []

    def __del__(self):
        self._cleanup()


class YaraRunner(Runner):
    """
    Runner which detects which parser to run on a given file based on YARA matching.
    YARA signatures must have the "mwcp" metadata field set to match a signature to one or more parsers
    to run.

    An initial parser can be provided for parsing the initial input file if you only want the YARA
    matching to happen with unidentified residual files.

    :param yara_repo: Path to directory of yara signatures.
    :param recursive: Whether to recursively match and run parsers for unidentified files.
    """

    def __init__(
            self, *,
            yara_repo: Union[str, pathlib.Path],
            recursive: bool = True,
            **report_config,
    ):
        super().__init__(**report_config)
        self._rules = self.compile_rules(pathlib.Path(yara_repo))
        self._recursive = recursive
        self._attempted = set()  # Keep track of files we have already attempted to parse.

    def compile_rules(self, yara_repo: pathlib.Path) -> yara.Rules:
        if not yara_repo.exists():
            raise RuntimeError(f"Unable to locate: {yara_repo}")
        # Collect and validate rule files.
        rule_paths = []
        for file_path in yara_repo.rglob("*"):
            if file_path.suffix in (".yara", ".yar"):
                # Make sure rule file compiles successfully before including.
                # TODO: Determine if there is a way we can filter out rules without any "mwcp" metadata.
                #   And possibly validate the provided parser names as well?
                try:
                    yara.compile(filepath=str(file_path))
                    rule_paths.append(file_path)
                except yara.Error as e:
                    logger.warning(f"[Skipping Rules] Failed to compile: {e}")

        return yara.compile(filepaths={path.name: str(path) for path in rule_paths})

    def iter_parsers(self, file_object: FileObject, parser: Union[str, Parser] = None) -> Iterable[Parser]:
        """
        Run YARA rules to detect which parsers to run.
        """
        # If user provided a parser, use that.
        if parser:
            if isinstance(parser, str):
                for _, parser in iter_parsers(parser):
                    yield parser
            else:
                yield parser
            return

        # Otherwise, run YARA to detect which parsers to run.
        seen = set()
        logger.info(f"Attempting to YARA match {file_object.name}")
        matched = False
        for match in self._rules.match(data=file_object.data):
            logger.debug(f"Matched {file_object.name} with YARA rule: {match.rule}")
            if "mwcp" in match.meta:
                mwcp_meta = match.meta["mwcp"]
                logger.debug(f"Mapped {file_object.name}: {mwcp_meta}")
                parser_names = [name.strip() for name in mwcp_meta.split(",")]
                for name in parser_names:
                    for source, parser in iter_parsers(name):
                        if (source.name, parser.name) not in seen:
                            seen.add((source.name, parser.name))
                            logger.info(f"Matched {file_object.name} with {parser.name} parser.")
                            matched = True
                            yield parser
        if not matched:
            logger.info(f"Found no YARA matches for {file_object.name}")

    def _parse(self, input_file: FileObject, parsers: Iterable[Parser], report: Report):
        self._attempted.add(input_file)
        super()._parse(input_file, parsers, report)
        # After parsing the file, recursively process any undefined dispatched files.
        if self._recursive:
            for child in input_file.descendants:
                if child.parser == UnidentifiedFile and child not in self._attempted:
                    parsers = list(self.iter_parsers(child))
                    if not parsers:
                        self._attempted.add(child)  # Avoid running yara multiple times.
                        continue
                    # Clear identification markings and try again.
                    child.parser = None
                    child.description = None
                    self._parse(child, parsers, report)

    def run(
            self,
            parser: Union[str, Parser] = None,
            file_path: Union[str, pathlib.Path] = None,
            data: bytes = None,
    ) -> Report:
        """
        Runs specified parser on file

        :param parser: name or class of parser to run.
            If left blank, YARA will be used to determine what parser(s) to start with.
        :param file_path: file to parse
        :param data: use data as file instead of loading data from filename

        :returns: Report object containing parse results.
        """
        input_file = self._generate_input_file(file_path, data)

        parser_name = parser
        if parser and not isinstance(parser, str):
            parser_name = parser.__name__

        report = Report(input_file=input_file, parser=parser_name or "-", **self._report_config)

        # We also have to include the report in the input_file incase the parser tries to dereference
        # reporter.
        # TODO: Remove this on a major release.
        input_file._report = report

        with report, OutputLogger():
            try:
                parsers = self.iter_parsers(input_file, parser)
                self._parse(input_file, parsers, report)
                return report
            finally:
                self._cleanup()
