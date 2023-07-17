"""
Interface for Report class.
"""
import base64
import collections
import io
import json
import logging
import pathlib
import re
import warnings
from copy import deepcopy
from typing import Union, Iterable, Optional, Type, Tuple, List, Callable, TypeVar
import weakref

import pandas
from anytree import RenderTree

import mwcp
from mwcp import config, metadata, FileObject
from mwcp.metadata import Report as ReportModel, Metadata, File
from mwcp.report_writers import DataFrameWriter, SimpleTextWriter, MarkdownWriter, HTMLWriter
from mwcp.stix.report_writer import STIXWriter
from mwcp.utils import logutil
from mwcp.utils.stringutils import convert_to_unicode, sanitize_filename

logger = logging.getLogger(__name__)


# Maps legacy field names to their metadata.Element or helper function.
METADATA_MAP = {
    "address": metadata.Address,
    "base16_alphabet": metadata.Base16Alphabet,
    "base32_alphabet": metadata.Base32Alphabet,
    "base64_alphabet": metadata.Base64Alphabet,
    "c2_address": metadata.C2Address,
    "c2_socketaddress": metadata.C2SocketAddress,
    "c2_url": metadata.C2URL,
    "credential": metadata.Credential,
    "directory": metadata.Directory,
    "email_address": metadata.EmailAddress,
    "event": metadata.Event,
    "filename": metadata.FileName,
    "filepath": metadata.FilePath,
    "ftp": metadata.FTP,
    "guid": metadata.UUIDLegacy,
    "injectionprocess": metadata.InjectionProcess,
    "interval": metadata.IntervalLegacy,
    "key": metadata.EncryptionKeyLegacy,
    "listenport": metadata.ListenPort,
    "missionid": metadata.MissionID,
    "mutex": metadata.Mutex,
    "other": metadata.Other,
    "outputfile": metadata.File,
    "password": metadata.Password,
    "pipe": metadata.Pipe,
    "port": metadata.Port,
    "proxy": metadata.Proxy,
    "proxy_socketaddress": metadata.ProxySocketAddress,
    "proxy_address": metadata.ProxyAddress,
    "registrydata": metadata.RegistryData,
    "registrypath": metadata.RegistryPath,
    "registrypathdata": metadata.RegistryPathData,
    "rsa_private_key": metadata.RSAPrivateKey,
    "rsa_public_key": metadata.RSAPublicKey,
    "service": metadata.Service,
    "servicedescription": metadata.ServiceDescription,
    "servicedisplayname": metadata.ServiceDisplayName,
    "servicedll": metadata.ServiceDLL,
    "serviceimage": metadata.ServiceImage,
    "servicename": metadata.ServiceName,
    "socketaddress": metadata.SocketAddress,
    "ssl_cert_sha1": metadata.SSLCertSHA1,
    "url": metadata.URL,
    "urlpath": metadata.URLPath,
    "useragent": metadata.UserAgent,
    "username": metadata.Username,
    "version": metadata.Version,
}


LogRecord = collections.namedtuple("LogRecord", ["source", "level", "message"])


class ReportLogHandler(logging.Handler):
    """
    Custom logging handler used to record log message into the generated Report.
    """

    def __init__(self, report: "Report"):
        super().__init__()
        self._report_ref = weakref.ref(report)

    def emit(self, record):
        if report := self._report_ref():
            message = self.format(record)
            report._logs.append(LogRecord(report._current_file, record.levelno, message))


T = TypeVar("T")


class Report:
    """
    Interface for building and accessing reportable information during parsing.

    :param input_file: The original input file that started the parsing. (The root file)
    :param parser: The name of the parser used for parsing.
    :param recursive: Whether to recursively process unidentified files using YARA matching.
    :param knowledge_base: External information to provide to the parsers. (e.g. encryption keys)
    :param include_logs: Whether to include error and debug logs in the generated report.
    :param include_file_data: Whether to include file data in the generated report.
        If disabled, only the file path, description, and md5 will be included.
    :param prefix_output_files: Whether to include a prefix of the first 5 characters
        of the md5 on output files. This is to help avoid overwriting multiple
        output files with the same name.
    :param log_level: If including logs, the logging level to be collected.
        (Defaults to currently set effective log level)
    :param log_filter: If including logs, this can be used to pass in a custom filter for the logs.
        Should be a valid argument for logging.Handler.addFilter()
    :param external_strings_report: Whether to output reported DecodedString elements into a
        separate strings report.
    """

    def __init__(
            self,
            input_file: mwcp.FileObject = None,
            parser: str = None,
            *,
            recursive: bool = False,
            knowledge_base: dict = None,
            include_logs: bool = True,
            include_file_data: bool = False,
            prefix_output_files: bool = True,
            output_directory: Union[pathlib.Path, str] = None,
            log_level: int = None,
            log_filter: logging.Filter = None,
            external_strings_report: bool = False,
    ):
        if output_directory:
            output_directory = pathlib.Path(output_directory)
            output_directory.mkdir(exist_ok=True)
        self._output_directory = output_directory
        self._write_output_files = bool(output_directory)

        self._include_logs = include_logs
        self._include_file_data = include_file_data
        self._prefix_output_files = prefix_output_files
        self._external_strings_report = external_strings_report

        self.input_file = input_file
        self.parser = parser
        self.recursive = recursive
        # Save a copy to prevent polluting the original.
        self.knowledge_base = dict(knowledge_base or {})
        # Save a copy as "external_knowledge" for saving into report.
        self._external_knowledge = dict(self.knowledge_base)
        self.tags = set()

        # Holds logs per file. (This is used by the ReportLogHandler)
        self._logs: List[LogRecord] = []
        # Holds metadata per file.
        self._metadata = collections.defaultdict(list)
        self._current_file = input_file  # type: FileObject
        self._history = [input_file]  # type: List[FileObject]
        self.parsed_files = {}
        self.finalized = False

        # Setup a log handler to add errors and debug messages to the report.
        if include_logs:
            log_handler = ReportLogHandler(self)
            logging.root.addHandler(log_handler)
            # Setup a simple format that doesn't contain any runtime variables.
            log_handler.addFilter(logutil.LevelCharFilter())
            log_handler.setFormatter(logging.Formatter("[%(level_char)s] %(message)s"))
            if log_level is not None:
                log_handler.setLevel(log_level)
            if log_filter is not None:
                log_handler.addFilter(log_filter)
            self._log_handler = log_handler
        else:
            self._log_handler = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.finalize()

    def _insert_into_other(self, metadata_dict: dict, key: str, value):
        """
        Handles inserting the given key/value pair into the other dictionary
        based on legacy logic.

        TODO: Remove this when we remove .metadata
        """
        other_dict = metadata_dict["other"]
        if key in other_dict:
            # this key already exists, we don't want to clobber so
            # we turn into list?
            existing_value = other_dict[key]
            if isinstance(existing_value, list):
                if value not in existing_value:
                    existing_value.append(value)
            elif value != existing_value:
                other_dict[key] = [existing_value, value]
        else:
            # normal insert of single value
            other_dict[key] = value

    @property
    def fields(self):
        warnings.warn(
            "Usage of the fields attribute is deprecated. ",
            DeprecationWarning
        )
        with open(config.get("FIELDS_PATH"), "rb") as f:
            return json.load(f)

    @property
    def external_knowledge(self) -> dict:
        """Provides copy of the initial knowledge_base provided by the user."""
        return dict(self._external_knowledge)  # copy to prevent parser from modifying.

    def get_logs(self, source: Optional[FileObject] = None, errors_only=False) -> List[str]:
        """
        Gets log messages.

        :param source: Filters only logs from given source file.
        :param errors_only: Filters only error messages.
        :return: list of log messages
        """
        return [
            record.message
            for record in self._logs
            if (
                (not source or record.source == source)
                and (not errors_only or record.level > logging.WARNING)
            )
        ]

    @property
    def logs(self) -> List[str]:
        """
        All logs within this report.
        """
        return self.get_logs()

    @property
    def errors(self) -> List[str]:
        """
        All error logs within this report.
        """
        return self.get_logs(errors_only=True)

    @property
    def metadata(self) -> dict:
        """
        Converts our metadata elements back into the legacy format described in fields.json

        NOTE: This is here for backwards compatibility with the old json format.
            Please update your code to use the new schema found in as_dict() or as_json()
        """
        warnings.warn(
            "metadata attribute is deprecated. Please access report data using "
            "as_dict(), as_json(), as_text(), etc.",
            DeprecationWarning
        )
        results = collections.defaultdict(list)
        # noinspection PyTypeChecker
        results["other"] = {}  # "other" is the only field that is not a list.
        for element in self:
            if isinstance(element, metadata.Path2):
                if element.is_dir:
                    results["directory"].append(element.path or element.directory_path)
                else:
                    if element.path:
                        results["filepath"].append(element.path)
                    if element.name:
                        results["filename"].append(element.name)
                    if element.directory_path:
                        results["directory"].append(element.directory_path)

            elif isinstance(element, metadata.Socket2):
                if element.address:
                    results["address"].append(element.address)
                    if "c2" in element.tags:
                        results["c2_address"].append(element.address)
                    if "proxy" in element.tags:
                        results["proxy_address"].append(element.address)

                socket_address = [
                    element.address or "",
                    str(element.port) if element.port is not None else "",
                    element.network_protocol or "",
                ]
                if element.port is not None:
                    # noinspection PyDataclass
                    if not element._from_port:  # user explicitly specified a Socket
                        results["socketaddress"].append(socket_address)
                        if "c2" in element.tags:
                            results["c2_socketaddress"].append(socket_address)
                        if "proxy" in element.tags:
                            results["proxy_socketaddress"].append(socket_address)

                    port = socket_address[1:]
                    if element.listen:
                        results["listenport"].append(port)
                    else:
                        results["port"].append(port)

            elif isinstance(element, metadata.Alphabet):
                if element.base in (16, 32, 64):
                    results[f"base{element.base}_alphabet"].append(element.alphabet)
                else:
                    # noinspection PyTypeChecker
                    self._insert_into_other(
                        results, f"base{element.base}_alphabet", element.alphabet)

            elif isinstance(element, metadata.Command):
                self._insert_into_other(results, "command", element.value)

            elif isinstance(element, metadata.CryptoAddress):
                symbol = (element.symbol or "crypto").lower()
                self._insert_into_other(results, f"{symbol}_address", element.address)

            elif isinstance(element, metadata.URL2):
                if element.url:
                    results["url"].append(element.url)
                    if "c2" in element.tags:
                        results["c2_url"].append(element.url)
                if element.path:
                    results["urlpath"].append(element.path)
                    if "c2" in element.tags and not element.url:
                        results["c2_url"].append(element.path)

            elif isinstance(element, metadata.Network):
                if element.socket and element.credential and "proxy" in element.socket.tags:
                    results["proxy"].append([
                        element.credential.username,
                        element.credential.password,
                        element.socket.address or "",
                        str(element.socket.port),
                        element.socket.network_protocol or ""
                    ])
                if element.url and element.url.protocol == "ftp":
                    result = []
                    if element.url.url:
                        result.extend([element.url.url])
                    if element.socket:
                        result.extend([
                            element.socket.address or "",
                            str(element.socket.port),
                            element.socket.network_protocol or ""
                        ])
                    result.extend([element.credential.username, element.credential.password])
                    results["ftp"].append(result)
            elif isinstance(element, metadata.Credential):
                if element.username and element.password:
                    results["credential"].append([element.username, element.password])
                if element.username:
                    results["username"].append(element.username)
                if element.password:
                    results["password"].append(element.password)

            elif isinstance(element, metadata.EmailAddress):
                results["email_address"].append(str(element.value))

            elif isinstance(element, metadata.Event):
                results["event"].append(str(element.value))

            elif isinstance(element, (metadata.UUID, metadata.UUIDLegacy)):
                results["guid"].append(str(element.value))

            elif isinstance(element, metadata.InjectionProcess):
                results["injectionprocess"].append(str(element.value))

            elif isinstance(element, (metadata.Interval, metadata.IntervalLegacy)):
                results["interval"].append(str(element.value))

            elif isinstance(element, metadata.EncryptionKey):
                key = element.key
                if element._legacy:
                    key = key.decode("utf-8")
                else:
                    # Display key as hex string for old display.
                    key = f"0x{key.hex()}"
                results["key"].append(key)
                if element.algorithm:
                    # noinspection PyTypeChecker
                    self._insert_into_other(results, f"{element.algorithm}_key", key)

            elif isinstance(element, metadata.MissionID):
                results["missionid"].append(str(element.value))

            elif isinstance(element, metadata.Mutex):
                results["mutex"].append(str(element.value))

            elif isinstance(element, metadata.Other):
                value = element.value
                if isinstance(value, bytes):
                    value = value.decode("latin1")
                # noinspection PyTypeChecker
                self._insert_into_other(results, element.key, value)

            elif isinstance(element, metadata.Pipe):
                results["pipe"].append(str(element.value))

            elif isinstance(element, metadata.Registry2):
                if element.data:
                    results["registrydata"].append(str(element.data))
                if element.key or element.value:
                    path = "\\".join([element.key or "", element.value or ""])
                    results["registrypath"].append(path)
                    if element.data:
                        results["registrypathdata"].append([path, str(element.data)])

            elif isinstance(element, metadata.RSAPrivateKey):
                results["rsa_private_key"].append([
                    element.public_exponent and hex(element.public_exponent),
                    element.modulus and hex(element.modulus),
                    element.private_exponent and hex(element.private_exponent),
                    element.p and hex(element.p),
                    element.q and hex(element.q),
                    element.d_mod_p1 and hex(element.d_mod_p1),
                    element.d_mod_q1 and hex(element.d_mod_q1),
                    element.q_inv_mod_p and hex(element.q_inv_mod_p),
                ])

            elif isinstance(element, metadata.RSAPublicKey):
                results["rsa_public_key"].append([
                    element.public_exponent and hex(element.public_exponent),
                    element.modulus and hex(element.modulus),
                ])

            elif isinstance(element, metadata.Service):
                service = [
                    element.name,
                    element.display_name,
                    element.description,
                    element.image,
                    element.dll,
                ]
                if sum(x is not None for x in service) > 1:
                    results["service"].append(service)
                if element.description:
                    results["servicedescription"].append(element.description)
                if element.display_name:
                    results["servicedisplayname"].append(element.display_name)
                if element.dll:
                    results["servicedll"].append(element.dll)
                if element.image:
                    results["serviceimage"].append(element.image)
                if element.name:
                    results["servicename"].append(element.name)

            elif isinstance(element, metadata.SSLCertSHA1):
                results["ssl_cert_sha1"].append(str(element.value))

            elif isinstance(element, metadata.UserAgent):
                results["useragent"].append(str(element.value))

            elif isinstance(element, metadata.Version):
                results["version"].append(str(element.value))

            elif isinstance(element, metadata.File):
                output_file = [element.name, element.description, element.md5]
                if self._include_file_data and element.data:
                    output_file.append(base64.b64encode(element.data).decode())
                results["outputfile"].append(output_file)

            elif isinstance(element, metadata.DecodedString):
                self._insert_into_other(results, "decoded_string", element.value)

        # None is not a thing in the legacy schema.
        # Replace all None's with empty strings.
        for key, value in results.items():
            if isinstance(value, list):
                new_value = []
                for entry in value:
                    if entry is None:
                        entry = ""
                    elif isinstance(entry, list):
                        entry = [x if x is not None else "" for x in entry]
                    new_value.append(entry)
                results[key] = new_value

        if self.logs and self._include_logs:
            results["debug"] = self.logs

        # Remove "other" if we didn't end up using it.
        if not results["other"]:
            del results["other"]

        return dict(results)

    def _build_report_model(self, source: FileObject = None) -> ReportModel:
        """
        Generate metadata.Report object using currently added metadata.
        """
        input_file = source or self.input_file
        metadata_entries = self.get(source=source)
        report_model = metadata.Report(
            input_file=metadata.File.from_file_object(input_file) if input_file else None,
            parser=(input_file.parser and input_file.parser.name) if source else self.parser,
            recursive=self.recursive,
            external_knowledge=self.external_knowledge,
            errors=self.get_logs(source, errors_only=True),
            logs=self.get_logs(source),
            metadata=deepcopy(metadata_entries),
        ).add_tag(*self.tags)
        report_model.validate()

        # Remove DecodedString element if external strings report was requested.
        # (These are included as a supplemental file in the report.)
        if self._external_strings_report:
            report_model.metadata = [
                element for element in report_model.metadata if not isinstance(element, metadata.DecodedString)
            ]

        # Remove raw file data from report model if requested.
        if not self._include_file_data:
            if report_model.input_file:
                report_model.input_file.data = None
            for element in report_model.metadata:
                if isinstance(element, metadata.File):
                    element.data = None

        return report_model

    @property
    def _report_model(self) -> Union[ReportModel, List[ReportModel]]:
        """
        Returns the report model based on currently added metadata.
        Results are merged.
        """
        return self._build_report_model()

    @property
    def _report_models(self) -> List[ReportModel]:
        """
        Returns a list of report models split between each source file.
        """
        return [
            self._build_report_model(source=file_object)
            for file_object in sorted(self._metadata.keys(), key=lambda fo: self._history.index(fo))
        ]

    def as_dict(self) -> dict:
        """
        Returns dictionary representation of the report (merged).
        """
        return self._report_model.as_dict()

    def as_list(self) -> List[dict]:
        """
        Returns a list of dictionaries representing the report split by
        source file.
        """
        return [report_model.as_dict() for report_model in self._report_models]

    def as_dict_legacy(self, include_filename=False) -> dict:
        """
        Returns dictionary representation of the report. (LEGACY schema)
        """
        result = self.metadata
        # Include input file information.
        # (originally part of _parse_file in cli)
        if include_filename:
            input_file = metadata.File.from_file_object(self.input_file)
            result["inputfilename"] = input_file.file_path
            result["md5"] = input_file.md5
            result["sha1"] = input_file.sha1
            result["sha256"] = input_file.sha256
            result["parser"] = self.parser
            if input_file.compile_time:
                result["compiletime"] = input_file.compile_time

        if self.errors:
            result["errors"] = self.errors

        return result

    def as_json(self, split=False) -> str:
        """
        Returns json representation of the report.
        """
        if split:
            return json.dumps(
                [report_model.as_json_dict() for report_model in self._report_models]
            )
        else:
            return self._report_model.as_json()

    def as_json_dict(self, split=False):
        """
        Jsonifies the element and then loads it back as a dictionary.
        NOTE: This is different from .as_dict() because things like bytes
        will be converted to a base64 encoded string.
        """
        if split:
            return [report_model.as_json_dict() for report_model in self._report_models]
        else:
            return self._report_model.as_json_dict()

    def as_json_legacy(self, include_filename=False) -> str:
        """
        Returns json representation of the report. (LEGACY schema)
        """
        return json.dumps(self.as_dict_legacy(include_filename=include_filename), indent=4)

    def as_stix(self, writer=None, *, fixed_timestamp: str = None) -> str:
        """
        Returns JSON serialized STIX representation of the report.
        """
        if writer:
            warnings.warn(
                "Passing writer to .as_stix() is deprecated. Use write_stix() if writing multiple reports.",
                DeprecationWarning
            )
            self.write_stix(writer)
            return ""

        writer = STIXWriter(fixed_timestamp=fixed_timestamp)
        self.write_stix(writer)
        return writer.serialize()

    def write_stix(self, writer: STIXWriter):
        """
        Writes STIX representation of report to provided STIXWriter.
        """
        for report_model in self._report_models:
            writer.write(report_model)

    def as_text(self, format="simple", split=False) -> Optional[str]:
        """
        Returns a custom text representation of the report.

        :param format: Text format to use.
        :param split: Whether to split up metadata results by file or to merge all results
            under the initial input file.
        """
        format_map = {
            "simple": SimpleTextWriter,
            "markdown": MarkdownWriter,
            "html": HTMLWriter,
        }
        try:
            writer_class = format_map[format]
        except KeyError:
            raise ValueError(f"Invalid report format: {format}")

        stream = io.StringIO()
        with writer_class(stream) as writer:
            if split:
                for report_model in self._report_models:
                    writer.write(report_model)
            else:
                writer.write(self._report_model)

            # Write File tree
            if self.input_file:
                writer.h1("File Tree")
                writer.code_block(self.file_tree())

        return stream.getvalue()

    def as_markdown(self) -> str:
        return self.as_text("markdown")

    def as_html(self) -> str:
        return self.as_text("html")

    def as_dataframe(self, split=False) -> pandas.DataFrame:
        if split:
            return pandas.concat([
                DataFrameWriter().write(report_model)
                for report_model in self._report_models
            ])
        else:
            return DataFrameWriter().write(self._report_model)

    def as_csv(self) -> str:
        return self.as_dataframe().to_csv()

    def file_tree(self) -> str:
        """
        Returns a tree representing the files produced per....
        (this should just be part of text)
        :return:
        """
        return str(RenderTree(self.input_file))

    def strings(self, source: Union[None, str, FileObject] = None) -> List[str]:
        """
        Returns reported decoded string values.
        """
        return [element.value for element in self.iter(metadata.DecodedString, source=source)]

    def add_tag(self, *tags: Iterable[str]) -> "Report":
        """
        Adds global tag(s) to the report.
        NOTE: Tags added in this way are included in the overall report and aren't directed towards
        any specific file (including the original input file).

        :param tags: One or more tags to add to the metadata.
        :returns: Report object to make it chainable.
        """
        for tag in tags:
            self.tags.add(tag)
        return self

    def _get_metadata_element(self, field_name: str) -> Union[Metadata, Callable]:
        """
        Returns an appropriate metadata.Element or helper function based on given legacy field name.

        :param field_name: legacy field name
        :return: Either a metadata.Element or helper function to generate a metadata.Element.
        """
        try:
            return METADATA_MAP[field_name]
        except KeyError:
            raise KeyError(f"Invalid field name: {field_name}")

    def _convert_metadata_value(self, field_name: str, value):
        """
        Does any necessary conversion from legacy to new format.
        This is here for field conversions that we want to do to keep backwards compatibility,
        but we want to fail otherwise.

        :param field_name: Field name value comes from.
        :param value: Single value passed in for value.
        :return: New converted value.
        """
        # Ignore dictionaries for now (the other).
        if isinstance(value, dict):
            return value

        if isinstance(value, (list, tuple)):
            return [self._convert_metadata_value(field_name, x) for x in value]

        # Legacy metadata values did not support bytes at all. Must be strings.
        if isinstance(value, bytes):
            value = value.decode("latin1")

        if value == "":
            return None

        # Convert value for fields that expect hex strings.
        if (isinstance(value, str)
                and field_name in ("rsa_private_key", "rsa_public_key")
                and (value.startswith("0x") or re.search("[A-Fa-f]", value))
        ):
            return int(value, 16)

        return value

    def add(self, element: Metadata):
        """
        Report a metadata item.
        Supports both the new and old way of reporting.

        If element fails to validate, a error log message will be displayed
        instead of throwing an exception. This is so a parser won't completely stop
        on the first sign a new variant is partially breaking the parser.

        :param element: metadata.Element type to add.
        :raises mwcp.ValidationError: If given element is not valid.
        """
        if self.finalized:
            raise RuntimeError("Report has already been finalized. Metadata can no longer be added.")

        metadata_list = self._metadata[self._current_file]
        if element not in metadata_list:
            element.validate()
            metadata_list.append(element)
            element.post_processing(self)

    def remove(self, element: Metadata):
        """
        Remove metadata element from report.
        """
        if self.finalized:
            raise RuntimeError("Report has already been finalized. Metadata can no longer be removed.")

        for source, entries in self._metadata.items():
            if element in entries:
                entries.remove(element)

    def set_file(self, file_object: FileObject):
        """
        Sets the file currently being parsed.
        """
        self._current_file = file_object
        if file_object not in self._history:
            self._history.append(file_object)

    def add_metadata(self, field_name_or_element: Union[str, Metadata], value=None):
        """
        Report a metadata item.
        Supports both the new and old way of reporting.

        :param field_name_or_element: Either a metadata.Element or field name for value.
        :param value: string or list specifying the value of the metadata.
        :return:
        """
        warnings.warn(
            ".add_metadata() is deprecated in favor of .add() which only supports the new metadata elements.",
            DeprecationWarning
        )
        if isinstance(field_name_or_element, metadata.Metadata):
            self.add(field_name_or_element)
            return

        # Convert legacy metadata format into new format using metadata Element objects.

        field_name = convert_to_unicode(field_name_or_element)
        if value is None or all(not _value for _value in value):
            logger.debug(f"No values provided for {field_name}, skipping")
            return

        if field_name == "debug":
            self.logs.append(value)
            return

        element_class = self._get_metadata_element(field_name)
        value = self._convert_metadata_value(field_name, value)
        if isinstance(value, (list, tuple)):
            self.add(element_class(*value))
        elif field_name == "other":
            for key, _value in value.items():
                self.add(metadata.Other(key, _value))
        else:
            self.add(element_class(value))

    def output_file(self, data: bytes, filename: str = None, description: str = None):
        warnings.warn(
            "output_file() is deprecated. Please add a metadata.File object to add() instead.",
            DeprecationWarning
        )
        residual_file = metadata.File(name=filename, description=description, data=data)
        self.add(residual_file)
        # In order to be backwards compatible, we have to write out the file here, so we can
        # return a file path.
        return self._write_file(residual_file)

    def _write_file(self, file: File) -> Optional[str]:
        """
        Writes out the given File metadata object and returns the file path to the written file
        or None on failure.
        """
        if not self._write_output_files:
            return

        # Create a safe filename that won't have any name collisions.
        safe_filename = sanitize_filename(file.name)
        if self._prefix_output_files:
            safe_filename = f"{file.md5[:5]}_{safe_filename}"
        full_path = self._output_directory / safe_filename

        try:
            # TODO: Should we attach the real file path?
            full_path.write_bytes(file.data)
            logger.debug(f"Output file: {full_path}")
            full_path = str(full_path)
            file.file_path = full_path
            return full_path
        except Exception as e:
            logger.error(f"Failed to write output file {full_path} with error: {e}")
            return

    def finalize(self):
        """
        This should be called after parsing is complete.
        This performs post-processing tasks such as validation and cleaning up the log handler.
        """
        # If external string report enabled, create supplemental file containing
        # reported DecodedString elements.
        if self._external_strings_report:
            for file_object, metadata_list in self._metadata.items():
                string_report = metadata.StringReport(
                    file=metadata.File.from_file_object(file_object),
                    strings=[element for element in metadata_list if isinstance(element, metadata.DecodedString)]
                )
                string_report.file.data = None
                if string_report.strings:
                    self.add(metadata.SupplementalFile(
                        name=f"{file_object.name}_strings.json",
                        description=f"Decoded Strings",
                        data=string_report.as_json().encode("utf8"),
                    ))
                    self.add(metadata.SupplementalFile(
                        name=f"{file_object.name}_strings.txt",
                        description=f"Decoded Strings",
                        data="\n".join(string.value for string in string_report.strings).encode("utf8")
                    ))

        # TODO: move this to post_processing of File?
        # Write out residual files to file system if requested.
        if self._write_output_files:
            for residual_file in self.iter(metadata.File):
                self._write_file(residual_file)

        # Remove log handler.
        if self._log_handler:
            logging.root.removeHandler(self._log_handler)
            self._log_handler = None

        self.finalized = True

    def __iter__(self) -> Iterable[Metadata]:
        """
        Iterates the added metadata elements found within the Report.
        """
        yield from self.iter()

    def iter(
            self,
            *element_type: Type[T],
            source: Union[None, str, FileObject] = None
    ) -> Iterable[T]:
        """
        Iterates and returns all element instance of the given metadata Element class
        or tuple of Element classes.

        Iterates all elements if an element_type and source_file is not provided.

        e.g.
            for residual_file in report.iter(metadata.File):
                ...

            for element in report.iter(metadata.URL, metadata.Socket):
                ...

            for residual_file in report.iter(metadata.File, source="5d41402abc4b2a76b9719d911017c592"):
                ...

            for element in report.iter(metadata.URL, metadata.Socket, source="5d41402abc4b2a76b9719d911017c592"):
                ...
        """
        if source:
            if isinstance(source, str):
                for file_object in self._metadata.keys():
                    if file_object.md5 == source:
                        source = file_object
                        break
                else:
                    raise ValueError(f"Unable to find file with md5: {source}")
            metadata_lists = [self._metadata[source]]
        else:
            metadata_lists = self._metadata.values()

        yielded = []
        for metadata_list in metadata_lists:
            for element in metadata_list:
                for _element in element.elements():
                    if not element_type or isinstance(_element, element_type):
                        # Metadata elements are not hashable, so we need to check equality of each.
                        if not any(_element == yielded_element for yielded_element in yielded):
                            yielded.append(_element)
                            yield _element

    def get(
            self,
            *element_type: Type[T],
            source: Union[None, str, FileObject] = None
    ) -> List[T]:
        """
        Same as .iter(), but wraps results in a list for you.

        e.g.
            residual_files = report.get(metadata.File)
            residual_files = report.get(metadata.File, source="5d41402abc4b2a76b9719d911017c592")
            elements = report.get(metadata.URL, metadata.Socket)
            elements = report.get(metadata.URL, metadata.Socket, source="5d41402abc4b2a76b9719d911017c592")
        """
        return list(self.iter(*element_type, source=source))

    def iter_tagged(self, *tags) -> Iterable[Metadata]:
        """
        Iterates metadata elements with specific tags.

        :param *tags: Name of tags to get. Gets all elements that were tagged otherwise.
        """
        # If no tags provided, just get all elements that are tagged.
        if not tags:
            for element in self:
                if element.tags:
                    yield element
        else:
            for element in self:
                if any(tag in element.tags for tag in tags):
                    yield element

    def get_tagged(self, *tags) -> List[Metadata]:
        """
        Same as .iter_tagged(), but wraps the results in a list for you.
        """
        return list(self.iter_tagged(*tags))
