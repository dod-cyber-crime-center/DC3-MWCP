import abc
import collections
import html
import re
import textwrap
from typing import List, Union

import pandas
import tabulate

from mwcp import metadata


def _camel_case_to_title(name: str):
    """
    Converts CamelCase name to a formated title:

    >>> _camel_case_to_title("SocketURLAddress")
    "Socket URL Address"
    """
    # Remove any "2" suffixes. These are here for transitions to new schemas.
    name = name.rstrip("2")
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
            [md5, 0, category, "derivation", report.input_file.derivation],
        ])
        # Split tags into their own rows.
        for tag in report.input_file.tags:
            rows.append([md5, 0, category, "tag", tag])

        for meta_index, element in enumerate(report.metadata, start=1):
            category = _camel_case_to_title(element.__class__.__name__)
            row_dict = element.as_dict(flat=True)

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
    MAX_COL_WIDTH = 100
    MAX_COL_INT_WIDTH = 50

    def __init__(self, stream):
        self._stream = stream

    def _format_cell_value(self, value):
        """
        Converts given cell value into formatted value appropriate for a table cell.
        Returns formatted value or passes back original value if no formatting is necessary.
        """
        # Convert sets into sorted lists to ensure deterministic behaviour.
        if isinstance(value, set):
            value = sorted(set)

        # Present lists of strings as comma delimited string.
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            value = ", ".join(value)

        # Wrap really long values to multiple lines.
        if value:
            max_width = self.MAX_COL_WIDTH
            # As a special case, we are going to force huge integers (such as in RSAPrivateKey)
            # to be wrapped at a smaller width threshold.
            if isinstance(value, int):
                max_width = self.MAX_COL_INT_WIDTH

            col_width = max(len(line) for line in str(value).splitlines())
            if col_width > max_width:
                # For simple format, we don't have any borders showing different cells, so we are going
                # to indent subsequence lines to make it more obvious it is part of the same cell.
                indent = "  " if isinstance(self, SimpleTextWriter) else ""
                value = textwrap.fill(
                    str(value),
                    width=max_width,
                    subsequent_indent=indent,
                    tabsize=4,
                    replace_whitespace=False,
                )

        return value

    def table(self, tabular_data: Union[List[dict], List[list]], headers=None, **options):
        """
        Writes out tabular data as a table using tabulate library.

        :param tabular_data: A list of dicts or lists to represent tabular data.
        :param headers: Header option passed to tabulate. If not provided and tabular data
            contains dictionaries, it will use the keys.
        :param **options: Extra arguments to pass along to tabulate.
        """
        if tabular_data:
            if not headers and isinstance(tabular_data[0], dict):
                headers = "keys"

            for i, entry in enumerate(tabular_data):
                # Reformat cells as appropriate.
                if isinstance(entry, dict):
                    tabular_data[i] = {key: self._format_cell_value(value) for key, value in entry.items()}
                elif isinstance(entry, list):
                    # noinspection PyTypeChecker
                    tabular_data[i] = [self._format_cell_value(value) for value in entry]
                else:
                    raise ValueError(f"Invalid tabular data: {entry!r}")

        self._stream.write(tabulate.tabulate(tabular_data, headers=headers, tablefmt=self._tablefmt, **options))
        self._stream.write("\n\n")

    def _write_table(self, elements: List[metadata.Element]):
        tabular_data = []
        includes_tags = False
        for element in elements:
            entry = element.as_formatted_dict(flat=True)

            # Strip empty values (but keep tags in order to ensure it is first)
            entry = {
                key: value
                for key, value in entry.items()
                if (value or value == 0 or key == "tags")
            }

            if entry["tags"]:
                includes_tags = True
                # deduplicate tags list if child objects share same tag with parent object or each other
                entry["tags"] = sorted(set(entry["tags"]))

            # Convert key names into more friendly titles.
            for key in list(entry.keys()):
                entry[key.replace("_", " ").replace(".", " / ").title()] = entry.pop(key)

            tabular_data.append(entry)

        # Decide if we should remove tags if no entries have tags.
        if not includes_tags:
            for entry in tabular_data:
                del entry["Tags"]

        if isinstance(elements[0], metadata.Version):
            # tabulate may incorrectly see these versions as floats.
            self.table(tabular_data, disable_numparse=True)
        else:
            self.table(tabular_data)

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
            ]
            if input_file.derivation:
                tabular_data.append(["Derivation", input_file.derivation])
            if input_file.tags:
                tabular_data.append(["Tags", ", ".join(input_file.tags)])
            # For this view, we will include the global report tags in this table as well.
            if report.tags:
                tabular_data.append(["Report Tags", ", ".join(report.tags)])

            self.table(tabular_data, headers=["Field", "Value"])

        # Write any initial external knowledge provided by the user.
        if report.external_knowledge:
            self.h2("External Knowledge")
            tabular_data = sorted(map(list, report.external_knowledge.items()))
            self.table(tabular_data, headers=["Field", "Value"])

        # Consolidate metadata elements by their type.
        metadata_dict = collections.defaultdict(list)
        for element in report.metadata:
            metadata_dict[element.__class__].append(element)

        # Write all metadata elements in alphabetical order.
        # (Except for Other and ResidualFile which we will write at the end.)
        for element_class, elements in sorted(metadata_dict.items(), key=lambda tup: tup[0].__name__):
            if element_class in (metadata.Other, metadata.File):
                continue
            table_name = _camel_case_to_title(element_class.__name__)
            # Remove the " Legacy" part for legacy metadata fields.
            # NOTE: This can potentially lead to two different tables with the same header.
            #   But that would only happen if we are running a parser with a mixture of old and new.
            #   Developer should be proactive in completely updating the parsers in a set if they see this.
            if table_name.endswith(" Legacy"):
                table_name = table_name[:-len(" Legacy")]
            self.h2(table_name)
            self._write_table(elements)

        # Write Miscellaneous data
        misc_elements = metadata_dict.get(metadata.Other, [])
        if misc_elements:
            self.h2("Miscellaneous")
            self._write_table(misc_elements)

        # TODO: Use as_formatted_dict() instead?
        # Write out output/residual files. (Customized columns)
        residual_files = metadata_dict.get(metadata.File, [])
        if residual_files:
            self.h2("Residual Files")
            include_tags = any(residual_file.tags for residual_file in residual_files)
            tabular_data = []
            for residual_file in residual_files:
                row = [
                    residual_file.name,
                    residual_file.description,
                    residual_file.derivation,
                    residual_file.md5,
                    residual_file.architecture,
                    residual_file.compile_time
                ]
                if include_tags:
                    row = [", ".join(residual_file.tags)] + row
                tabular_data.append(row)
            headers = ["Filename", "Description", "Derivation", "MD5", "Arch", "Compile Time"]
            if include_tags:
                headers = ["Tags"] + headers
            self.table(tabular_data, headers=headers)

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

    def _format_cell_value(self, value):
        value = super()._format_cell_value(value)
        # We need to replace newlines with <br> since tabulate doesn't do that for us.
        if isinstance(value, str):
            value = value.replace("\n", "<br>")
        return value

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


class HTMLWriter(MarkupWriter):
    name = "html"
    # NOTE: Using unsafehtml format so we can escape the values ourselves.
    _tablefmt = "unsafehtml"

    def _format_cell_value(self, value):
        value = super()._format_cell_value(value)
        if isinstance(value, str):
            value = html.escape(value)
            # If we have newlines in the value, wrap it in <pre>
            # in order to preserve whitespace.
            if "\n" in value:
                value = f"<pre>{value}</pre>"
        return value

    def h1(self, text: str):
        self._stream.write(f"<h1>{html.escape(text)}</h1>\n")

    def h2(self, text: str):
        self._stream.write(f"<h2>{html.escape(text)}</h2>\n")

    def h3(self, text: str):
        self._stream.write(f"<h3>{html.escape(text)}</h3>\n")

    def code_block(self, text: str):
        if not text.endswith("\n"):
            text = text + "\n"
        self._stream.write(f"<pre>\n{html.escape(text)}</pre>\n\n")


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
