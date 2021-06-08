# TODO: change module name to singular?

import abc
import collections
import io
import re
from typing import List, Union

import pandas
import tabulate

from mwcp import metadata


def _flatten_dict(element_dict: dict) -> dict:
    new_dict = {}
    for key, value in element_dict.items():
        if value is None or value == "":
            continue
        if isinstance(value, dict):
            value.pop("type", None)
            tags = value.pop("tags", None)
            value = {
                f"{key}.{_key}" if _key in element_dict else _key: _value
                for _key, _value in _flatten_dict(value).items()
            }
            new_dict.update(value)

            # Consolidate tags into main dictionary.
            if tags:
                try:
                    new_dict["tags"].append(tags)
                except KeyError:
                    new_dict["tags"] = tags
        else:
            new_dict[key] = value

    # Pop off type.
    new_dict.pop("type", None)
    return new_dict


def _format_metadata_element(element: metadata.Element, join_tags=True, convert_field_names=True) -> dict:
    entry = _flatten_dict(element.as_dict())

    # Convert tags to a string.
    if join_tags and "tags" in entry:
        entry["tags"] = ", ".join(sorted(entry["tags"]))

    # Convert key names in into more friendly titles.
    if convert_field_names:
        for key in list(entry.keys()):
            entry[key.replace("_", " ").replace(".", " / ").title()] = entry.pop(key)

    return entry


def _camel_case_to_title(name: str):
    """
    Converts CamelCase name to a formated title:

    >>> _camel_case_to_title("SocketURLAddress")
    "Socket URL Address"
    """
    return re.sub(
        "([a-z])([A-Z])", "\g<1> \g<2>",
        re.sub("([A-Z][a-z])", " \g<1>", name).strip()
    )


class ReportWriter(metaclass=abc.ABCMeta):
    name = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    @abc.abstractmethod
    def write(self, report: metadata.Report):
        ...


class DataFrameWriter(ReportWriter):
    """
    Base class for report writers that use a dataframe
    """

    def write(self, report: metadata.Report) -> pandas.DataFrame:
        rows = []

        # Every row is going to contain the original input file md5 to use as an index.
        md5 = report.input_file.md5

        # Add input file info.
        category = "Input File"
        rows.extend([
            [md5, 0, category, "parser", report.parser],
            [md5, 0, category, "filename", report.input_file.name],
            [md5, 0, category, "description", report.input_file.description],
            [md5, 0, category, "architecture", report.input_file.architecture],
            [md5, 0, category, "compile_time", report.input_file.compile_time],
        ])
        # Split tags into their own rows.
        for tag in report.input_file.tags:
            rows.append([md5, 0, category, "tag", tag])

        for meta_index, element in enumerate(report.metadata, start=1):
            category = _camel_case_to_title(element.__class__.__name__)
            row_dict = _format_metadata_element(element, join_tags=False, convert_field_names=False)

            # Flatten "Other"
            if category == "Other":
                row_dict[row_dict["key"]] = row_dict["value"]
                del row_dict["key"]
                del row_dict["value"]

            for key, value in row_dict.items():
                # Split tags into their own rows.
                if key == "tags":
                    for tag in sorted(value):
                        rows.append([md5, meta_index, category, "tag", tag])
                else:
                    rows.append([md5, meta_index, category, key, value])

        df = pandas.DataFrame(rows, columns=["MD5", "MetaIndex", "Category", "Field", "Value"])
        # Set index so dataframe is multi-indexed by metadata element.
        df.set_index(["MD5", "MetaIndex", "Category", "Field"], inplace=True)
        return df


class MarkupWriter(ReportWriter):
    """
    Base class for report writers that use a markup language.
    """
    # Table format used when generating tables.
    _tablefmt = None

    def __init__(self, stream):
        self._stream = stream

    def table(self, data: Union[List[dict], List[list]], headers=None):
        if not headers and data and isinstance(data[0], dict):
            headers = "keys"
        # Present sets as comma delimited elements. (useful for tags)
        for entry in data:
            if isinstance(entry, dict):
                for key, value in entry.items():
                    if isinstance(value, set):
                        entry[key] = ", ".join(sorted(value))
            elif isinstance(entry, list):
                for i, value in enumerate(entry):
                    if isinstance(value, set):
                        entry[i] = ", ".join(sorted(value))
        self._stream.write(tabulate.tabulate(data, headers=headers, tablefmt=self._tablefmt))
        self._stream.write("\n\n")

    def _write_table(self, elements: List[metadata.Element]):
        tabular_data = [_format_metadata_element(element) for element in elements]
        self.table(tabular_data, headers="keys")

    def write(self, report: metadata.Report):
        """
        Writes report using a markup language.
        Each metadata type will be written out in its own table with some
        special cases.
        """
        # First write input file as a pivoted table.
        input_file = report.input_file
        if input_file:
            self.h1(f"File: {input_file.name}")
            tabular_data = [
                ["Parser", report.parser],
                ["File Path", input_file.file_path],
                ["Description", input_file.description],
                ["Architecture", input_file.architecture],
                ["MD5", input_file.md5],
                ["SHA1", input_file.sha1],
                ["SHA256", input_file.sha256],
                ["Compile Time", input_file.compile_time],
                ["Tags", ", ".join(input_file.tags)]
            ]
            self.table(tabular_data, headers=["Field", "Value"])

        # Consolidate metadata elements by their type.
        metadata_dict = collections.defaultdict(list)
        for element in report.metadata:
            metadata_dict[element.__class__].append(element)

        # Write all metadata elements in alphabetical order.
        # (Except for Other and ResidualFile which we will write at the end.)
        for element_class, elements in sorted(metadata_dict.items(), key=lambda tup: tup[0].__name__):
            if element_class in (metadata.Other, metadata.ResidualFile):
                continue
            self.h2(_camel_case_to_title(element_class.__name__))
            self._write_table(elements)

        # Write Miscellaneous data
        misc_elements = metadata_dict.get(metadata.Other, [])
        if misc_elements:
            self.h2("Miscellaneous")
            self._write_table(misc_elements)

        # Write out output/residual files. (Customized columns)
        residual_files = metadata_dict.get(metadata.ResidualFile, [])
        if residual_files:
            self.h2("Residual Files")
            tabular_data = [
                [", ".join(sorted(residual_file.tags)),
                 residual_file.name, residual_file.description, residual_file.md5,
                 residual_file.architecture, residual_file.compile_time]
                 for residual_file in residual_files
            ]
            self.table(tabular_data, headers=[
                "Tags", "Filename", "Description", "MD5", "Arch", "Compile Time"])

        # Finally write out log messages.
        if report.errors:
            self.h2("Errors")
            self.code_block("\n".join(report.errors))
        if report.logs:
            self.h2("Logs")
            self.code_block("\n".join(report.logs))

    @abc.abstractmethod
    def h1(self, text: str):
        ...

    @abc.abstractmethod
    def h2(self, text: str):
        ...

    @abc.abstractmethod
    def h3(self, text: str):
        ...

    @abc.abstractmethod
    def code_block(self, text: str):
        ...


class MarkdownWriter(MarkupWriter):
    name = "markdown"
    _tablefmt = "pipe"

    def h1(self, text: str):
        self._stream.write(f"# {text}\n")

    def h2(self, text: str):
        self._stream.write(f"## {text}\n")

    def h3(self, text: str):
        self._stream.write(f"### {text}\n")

    def code_block(self, text: str):
        if not text.endswith("\n"):
            text = text + "\n"
        self._stream.write(f"```\n{text}```\n\n")


class HTMLWriter(MarkdownWriter):
    name = "html"
    _tablefmt = "html"

    def h1(self, text: str):
        self._stream.write(f"<h1>{text}</h1>\n")

    def h2(self, text: str):
        self._stream.write(f"<h2>{text}</h2>\n")

    def h3(self, text: str):
        self._stream.write(f"<h3>{text}</h3>\n")

    def code_block(self, text: str):
        if not text.endswith("\n"):
            text = text + "\n"
        # TODO: Escape html characters?
        self._stream.write(f"<pre>\n{text}</pre>\n\n")


class SimpleTextWriter(MarkupWriter):
    name = "simple"
    _tablefmt = "simple"

    def h1(self, text: str):
        self._stream.write(f"----- {text} -----\n")

    def h2(self, text: str):
        self._stream.write(f"---- {text} ----\n")

    def h3(self, text: str):
        self._stream.write(f"--- {text} ---\n")

    def code_block(self, text: str):
        if not text.endswith("\n"):
            text = text + "\n"
        self._stream.write(text + "\n")
