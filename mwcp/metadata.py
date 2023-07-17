"""
Schema for reportable metadata.

- Using attrs for easy of use and validation.
"""
import base64
import binascii
import hashlib
import inspect
import io
import json
import logging
import pathlib
import re
import textwrap
import warnings
import ntpath
from enum import IntEnum
import uuid
import typing
from typing import Any, Union, List, Optional, TypeVar, Type, Dict

from stix2 import v21 as stix

import attr
from bitarray import bitarray
import cattr
from defusedxml import ElementTree
import jsonschema_extractor
from pyasn1.codec.der import decoder as asn1_decoder
from pyasn1_modules import rfc2437, rfc2459, pem
from pyasn1.error import PyAsn1Error

import mwcp
from mwcp.exceptions import ValidationError
from mwcp.utils import construct
from mwcp.stix import extensions as stix_extensions
from mwcp.stix.objects import STIXResult

logger = logging.getLogger(__name__)


cattr = cattr.GenConverter()

# Register support for pathlib.
cattr.register_structure_hook(pathlib.Path, lambda d, t: pathlib.Path(d))
cattr.register_unstructure_hook(pathlib.Path, str)

# Register support for enums.
cattr.register_structure_hook(IntEnum, lambda d, t: t[d.upper()] if isinstance(d, str) else t(d))
cattr.register_unstructure_hook(IntEnum, lambda d: None if d is None else d.name)


T = TypeVar("T")


def _cast(value: Any, type_: Type[T]) -> T:
    """
    Casts given value to the given type.
    Usually uses cattr.structure()
    :param value: Value to cast.
    :param type_: Type to cast to.
        (For things like Union, it will try each type listed
        within, until one works.)
    :return: Converted value.
    """
    # Convert bytes to string, Python 2 style!
    if type_ is str and isinstance(value, bytes):
        return value.decode("latin1")

    # Prevent accidentally casting an integer to bytes.
    # Since bytes(some_int) will cause it to create a zero byte string with that many bytes,
    # this can stall or crash the process if the integer is large enough.
    if type_ is bytes and isinstance(value, int):
        raise ValueError("Cannot convert int to bytes.")

    if typing.get_origin(type_) is dict:
        key_type, value_type = typing.get_args(type_)
        return {_cast(key, key_type): _cast(value, value_type) for key, value in value.items()}

    # cattr doesn't handle Unions very nicely, so we'll recursively
    # handle the innards of Union types instead.
    # NOTE: Based on documentation, the cattr devs will eventually provide
    # better support for Unions in the future.
    if typing.get_origin(type_) is Union:
        # First see if value is already one of the types.
        if type(value) in type_.__args__:
            return value
        # Otherwise, attempt to case using types in order they are found in the Union.
        for sub_type in type_.__args__:
            try:
                return _cast(value, sub_type)
            except Exception:
                continue
        raise ValueError("No subtypes matched.")

    # Otherwise use cattr
    return cattr.structure(value, type_)


def _auto_convert(cls, fields):
    """
    Automatically applies type coercion to all fields.
    (This also acts as validation)
    """
    def converter(field_type):
        def _wrapper(v):
            if v is None:
                return v
            try:
                return _cast(v, field_type)
            except Exception as e:
                raise ValidationError(f"Failed to cast {v!r} to {field_type} with error: {e}")
        return _wrapper

    new_fields = []
    for field in fields:
        if field.converter is None and field.type:
            field = field.evolve(converter=converter(field.type))
        new_fields.append(field)
    return new_fields


def _camel_to_snake(name):
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def _strip_null(d: dict) -> dict:
    """
    Strips away any entries that have the value None.
    """
    new_dict = {}
    for key, value in d.items():
        if isinstance(value, dict):
            value = _strip_null(value)
        if value is not None:
            new_dict[key] = value
    return new_dict


def _flatten_dict(dict_: dict) -> dict:
    """
    Flattens given element dictionary into a single level of key/value pairs.
    Combines tags into one.
    """
    new_dict = {}
    for key, value in dict_.items():
        if isinstance(value, dict):
            value.pop("type", None)
            tags = value.pop("tags", None)
            value = {
                f"{key}.{_key}" if _key in dict_ else _key: _value
                for _key, _value in _flatten_dict(value).items()
            }
            new_dict.update(value)

            # Consolidate tags into main dictionary.
            if tags:
                try:
                    new_dict["tags"].extend(tags)
                except KeyError:
                    new_dict["tags"] = tags
        else:
            new_dict[key] = value

    # Pop off type.
    new_dict.pop("type", None)
    return new_dict


# Global configuration for all elements.
config = dict(auto_attribs=True, field_transformer=_auto_convert)


@attr.s(**config)
class Element:
    """
    Base class for handling reporting elements.
    These should be created using attr for convenience.
    """
    tags: List[str] = attr.ib(init=False, factory=list)

    _registry = {}
    _STIX_NAMESPACE = uuid.UUID("27b16a6a-0f3e-44e2-af1f-4b1c590278f4")

    def __init_subclass__(cls, **kwargs):
        """
        Registers all subclasses of Element.
        """
        typ = cls._type()
        if not typ.startswith("_") and typ != "metadata":
            if typ in cls._registry:
                raise ValueError(f"Metadata element of type {typ} already exists.")
            cls._registry[typ] = cls
        super().__init_subclass__(**kwargs)

    @classmethod
    def _all_subclasses(cls):
        """
        Returns all registered subclasses of the class, sorted by type.
        """
        return [
            subclass
            for _, subclass in sorted(cls._registry.items())
            if issubclass(subclass, cls) and subclass != cls
        ]

    @classmethod
    def _get_subclass(cls, type_name: str) -> Optional[Type["Element"]]:
        """
        Obtains subclass from given type.
        """
        try:
            subclass = cls._registry[type_name]
            if issubclass(subclass, cls) and subclass != cls:
                return subclass
        except KeyError:
            return

    @classmethod
    def _type(cls):
        """This function is used to determine name identifier for the """
        # By default, type is determined by class name.
        return _camel_to_snake(cls.__name__)

    @classmethod
    def _structure(cls, value: dict) -> "Element":
        """
        cattr hook for structuring Element class.
        """
        # Determine class to use based on "type" field.
        # Then call that class's _structure() function.
        type_ = value.pop("type", None)
        if type_ and type_ != cls._type():
            klass = cls._get_subclass(type_)
            if not klass:
                raise ValueError(f"Invalid type name: {type_}")
            return klass._structure(value)

        # Remove None values from dictionary, since that seems to be causing
        # cattr (or our autocasting) to convert them to the string "None"
        # TODO: Remove when github.com/python-attrs/cattrs/issues/53 is solved.
        value = _strip_null(value)

        # cattrs doesn't support init=False values, so we need to remove tags and
        # then re-add them.
        tags = value.pop("tags", [])
        ret = cattr.structure_attrs_fromdict(value, cls)
        ret.tags = tags
        return ret

    def _unstructure(self) -> dict:
        # Add "type" field to help with serialization.
        return {"type": self._type(), **cattr.unstructure_attrs_asdict(self)}

    @classmethod
    def fields(cls):
        return attr.fields(cls)

    @classmethod
    def _schema(cls, extractor):
        """
        Generates schema for this particular Element class.
        """
        # First get the short description by looking for the first complete sentence.
        description = []
        for line in inspect.getdoc(cls).splitlines():
            # Stop when we hit an empty line or see variable statements.
            if not line or line.startswith(":"):
                break
            description.append(line.strip())
        description = " ".join(description)

        schema = {
            "title": cls.__name__.strip("_").rstrip("2"),
            "description": description,
            "type": "object",
            "properties": {
                # Include the "type" property that gets added dynamically during serialization.
                "type": {
                    "const": cls._type(),
                }
            },
            "additionalProperties": False,
            "required": ["type"],
        }
        for field in cls.fields():
            is_required = field.default is not None

            # Allow customization within attr metadata field for corner cases.
            if "jsonschema" in field.metadata:
                sub_schema = field.metadata["jsonschema"]
            else:
                sub_schema = extractor.extract(field.type)

            # Anything not required is nullable.
            if not is_required:
                if list(sub_schema.keys()) == ["type"]:
                    if isinstance(sub_schema["type"], list):
                        if "null" not in sub_schema["type"]:
                            sub_schema["type"].append("null")
                    elif sub_schema["type"] != "null":
                        sub_schema["type"] = [sub_schema["type"], "null"]
                elif list(sub_schema.keys()) == ["anyOf"]:
                    if {"type": "null"} not in sub_schema["anyOf"]:
                        sub_schema["anyOf"].append({"type": "null"})
                else:
                    sub_schema = {"anyOf": [sub_schema, {"type": "null"}]}

            schema["properties"][field.name] = sub_schema

            if is_required:
                schema["required"].append(field.name)

        return schema

    @classmethod
    def schema(cls) -> dict:
        """
        Generates a JSONSchema from the given element.
        :return: Dictionary representing the schema.
        """
        typing_extractor = jsonschema_extractor.TypingExtractor()
        typing_extractor.register(Element, lambda extractor, typ: typ._schema(extractor))
        typing_extractor.register(bytes, lambda extractor, typ: {
            "type": "string",
            "contentEncoding": "base64",
        })
        # IntEnums are converted to their names before serialization by cattr.
        typing_extractor.register(IntEnum, lambda extractor, typ: {
            "enum": [c.name for c in typ]
        })
        extractor = jsonschema_extractor.SchemaExtractorSet([typing_extractor])
        return extractor.extract(cls)

    @classmethod
    def from_dict(cls, obj: dict) -> "Element":
        return cattr.structure(obj.copy(), cls)

    def as_dict(self, flat=False) -> dict:
        ret = cattr.unstructure(self)
        if flat:
            ret = _flatten_dict(ret)
        return ret

    def _format_value(self, value):
        # Convert bytes to a string representation.
        if isinstance(value, bytes):
            value = str(value)
        if isinstance(value, list):
            value = list(map(self._format_value, value))
        # Recursively handle nested elements.
        if isinstance(value, Element):
            value = value.as_formatted_dict()
        return value

    def as_formatted_dict(self, flat=False) -> dict:
        """
        Converts metadata element into a well formatted dictionary usually
        used for presenting metadata elements as tabular data.
        """
        ret = {}
        for field in self.fields():
            name = field.name
            value = getattr(self, name)
            ret[name] = self._format_value(value)

        if flat:
            ret = _flatten_dict(ret)
        return ret

    def as_json(self) -> str:
        class _JSONEncoder(json.JSONEncoder):
            def default(self, o):
                # Encode Collection objects using as_dict()
                if isinstance(o, Element):
                    return o.as_dict()
                # Encode bytes as base64
                if isinstance(o, bytes):
                    return base64.b64encode(o).decode()
                # Convert sets to list
                if isinstance(o, set):
                    return sorted(o)
                # Convert UUID
                if isinstance(o, uuid.UUID):
                    return str(o)
                return super().default(o)
        return json.dumps(self, cls=_JSONEncoder, indent=4)

    def as_json_dict(self) -> dict:
        """
        Jsonifies the element and then loads it back as a dictionary.
        NOTE: This is different from .as_dict() because things like bytes
        will be converted to a base64 encoded string.
        """
        return json.loads(self.as_json())

    def validate(self):
        attr.validate(self)

    def elements(self) -> List["Element"]:
        """
        All elements contained within the given element. (including self)
        """
        elements = [self]
        for field in self.fields():
            value = getattr(self, field.name)
            if isinstance(value, Element):
                elements.extend(value.elements())
            elif isinstance(value, list):
                for sub_value in value:
                    if isinstance(sub_value, Element):
                        elements.extend(sub_value.elements())
        return elements

    def post_processing(self, report):
        """
        Performs and adds extra additions to the Report when the Element gets created.
        :param report: mwcp Report used to add metadata.
        """

    def add_tag(self, *tags: str) -> "Element":
        """
        Adds a tag for the given metadata.

        :param tags: One or more tags to add to the metadata.
        :returns: self to make this function chainable.
        """
        for tag in tags:
            if tag not in self.tags:
                self.tags.append(tag)
        # Ensure we keep the tags sorted.
        self.tags = sorted(self.tags)
        return self

# Value may be partially converted
# github.com/python-attrs/cattrs/issues/78
cattr.register_structure_hook(
    Element,
    lambda value, cls: value if hasattr(value, "__attrs_attrs__") else cls._structure(dict(value))
)

# obj may be None because we don't use Optional in our Typing.
cattr.register_unstructure_hook(Element, lambda obj: None if obj is None else obj._unstructure())


class Metadata(Element):
    """
    Represents a collection of reportable metadata attributes that together represent an idea.

    This class can be subclassed to create your own reportable metadata element.
    """

    @classmethod
    def _schema(cls, extractor):
        # If we are typing the base Metadata class, this means we want to represent
        # all subclasses instead.
        if cls == Metadata:
            return {"anyOf": [
                extractor.extract(subclass) for subclass in Metadata._all_subclasses()
            ]}
        else:
            return super()._schema(extractor)
    
    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        """
        Returns STIX content for a class.  All metadata objects should implement this, but if one does not a warning will be supplied.

        """
        warnings.warn(
            "as_stix is not implmeneted by " + type(self).__name__ + " so data may be missing from the result",
            UserWarning
        )
        return STIXResult()

    def as_stix_tags(self, parent, fixed_timestamp=None):
        """
        Returns an object containing tag information for a given parent assuming there is content
        """
        if self.tags:
            return stix.Note(
                labels=self.tags,
                content=f"MWCP Tags: {', '.join(self.tags)}",
                object_refs=[parent.id],
                created=fixed_timestamp,
                modified=fixed_timestamp,
                allow_custom=True
            )


@attr.s(**config)
class Path2(Metadata):
    r"""
    Filesystem path used by malware.

    Current directory (".") represents the directory of the malware sample that produced this metadata.

    e.g.
        Path2(r"C:\windows\temp\1\log\keydb.txt", is_dir=False)  # pass full path
        Path2(r"C:\foo\logs", is_dir=True)
        Path2("bar.exe", is_dir=False)  # Represents a file name with unknown location
        Path2(".\bar.exe", is_dir=False)  # Represents a file path within the same directory as the source malware sample.
    """
    path: str
    is_dir: bool = None
    posix: bool = None
    file_system: str = None  # NTFS, ext4, etc.

    def __attrs_post_init__(self):
        # If posix wasn't provided, determine this based on presence of drive letter or separator.
        if self.posix is None and (self.path.count("\\") or self.path.count("/")):
            self.posix = not (re.match("^[A-Z]:\\\\", self.path) or self.path.count("\\") > self.path.count("/"))

    @classmethod
    def _type(cls):
        return "path"

    @classmethod
    def from_segments(cls, *segments: str, is_dir: bool = None, posix: bool = False, file_system: str = None):
        """
        Provides ability to construct a Path from segments.
        NOTE: Path is assumed to be Windows if posix flag is not provided.

        e.g.
            Path2.from_segments("C:", "windows", "temp", "1", "log", "keydb.txt", posix=False, is_dir=False)
        """
        if not segments:
            raise ValidationError(f"from_segments() requires at least one segment.")
        if len(segments) == 1:
            return Path2(segments[0], is_dir=is_dir, posix=posix, file_system=file_system)

        # Ensure we do not have secondary segments starting with a slash.
        # This would cause pathlib's constructor to just take the last absolute path ignored the ones before it.
        # Which is something we don't want in this context.
        slash = "/" if posix else "\\"
        segments = [segments[0], *(segment.lstrip(slash) for segment in segments[1:])]

        if posix:
            path = pathlib.PurePosixPath(*segments)
        else:
            segments = list(segments)
            # If first segment is a drive, we need to include the \ in order for pathlib to see it as such.
            if segments[0].endswith(":"):
                segments[0] += "\\"
            path = pathlib.PureWindowsPath(*segments)
        return cls.from_pathlib_path(path, is_dir=is_dir, file_system=file_system)

    @classmethod
    def from_pathlib_path(cls, path: pathlib.PurePath, is_dir: bool = None, file_system: str = None):
        """
        Generate Path from pathlib.PurePath instance.
        """
        return Path2(str(path), is_dir=is_dir, posix=isinstance(path, pathlib.PurePosixPath), file_system=file_system)

    @property
    def _pathlib_path(self) -> Optional[pathlib.PurePath]:
        if self.posix is None:
            return None
        elif self.posix:
            return pathlib.PurePosixPath(self.path)
        else:
            return pathlib.PureWindowsPath(self.path)

    @property
    def directory_path(self) -> Optional[str]:
        if self.is_dir:
            return self.path
        else:
            path = self._pathlib_path
            if path:
                return str(path.parent)
            else:
                return None

    @property
    def name(self) -> str:
        path = self._pathlib_path
        if path:
            return path.name
        else:
            return self.path

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)

        if self.is_dir:
            result.add_linked(stix.Directory(path=self.path))
        else:
            file_data = {}

            if self.directory_path:
                cur_dir = stix.Directory(path=self.directory_path)
                result.add_unlinked(cur_dir)
                file_data["parent_directory_ref"] = cur_dir.id

            if self.name:
                file_data["name"] = self.name
                result.add_linked(stix.File(**file_data))

        result.create_tag_note(self, result.linked_stix[-1])

        return result


def Path(
        path: str = None,
        directory_path: str = None,
        name: str = None,
        is_dir: bool = None,
        file_system: str = None
) -> Path2:
    warnings.warn(
        "Path has been renamed to Path2 during a transitional period to a new version of Path " 
        "with a new signature. "
        "Please update to use Path2 which explicitly expects a path string with no directory/name separation."
        "NOTE: In a future version, once this function is deprecated, Path2 will be renamed back to Path "
        "using the new signature.",
        DeprecationWarning
    )
    # Replicating original logic. (existence of directory_path and name overwrite path)
    if directory_path and name:
        path = ntpath.join(directory_path, name)
    # If a directory_path was provided without a name, overwrite is_dir.
    elif directory_path and not name:
        path = directory_path
        is_dir = True
    elif name and not directory_path:
        path = name
        is_dir = False
    return Path2(path, is_dir=is_dir, file_system=file_system)


def Directory(path: str, posix: bool = None) -> Path2:
    return Path2(path, posix=posix, is_dir=True)


def FilePath(path: str, posix: bool = None) -> Path2:
    return Path2(path, posix=posix, is_dir=False)


def FileName(name: str) -> Path2:
    return Path2(name, is_dir=False)


@attr.s(**config)
class Alphabet(Metadata):
    """
    Generic baseXX alphabet
    """
    alphabet: str = attr.ib()
    base: int = attr.ib()

    @alphabet.validator
    def _validate_alphabet(self, attribute, value):
        alphabet = value
        base = self.base
        if alphabet and base:
            if len(alphabet) not in (base, base + 1):
                raise ValidationError(
                    "Invalid alphabet provided: "
                    "Length of alphabet must be size of base or base + 1 (if including the pad character)."
                )
            # TODO: Determine if this is a valid.
            # if len(alphabet) != len(set(alphabet)):
            #     raise ValidationError('mapping must be unique')

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        content = f"Alphabet: {self.alphabet}\nAlphabet Base: {self.base}"

        if self.tags:
            content += f"\n    Alphabet Tags: {', '.join(self.tags)}"

        return STIXResult(content)


def Base16Alphabet(alphabet: str) -> Alphabet:
    """
    Base16 alphabet

    e.g.
        Base16Alphabet("0123456789ABCDEF")
    """
    return Alphabet(alphabet=alphabet, base=16)


def Base32Alphabet(alphabet: str) -> Alphabet:
    """
    Base32 alphabet

    e.g.
        Base32Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
    """
    return Alphabet(alphabet=alphabet, base=32)


def Base64Alphabet(alphabet: str) -> Alphabet:
    """
    Base64 alphabet

    e.g.
        Base64Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    """
    return Alphabet(alphabet=alphabet, base=64)


@attr.s(**config)
class Command(Metadata):
    """
    Shell command

    :var value: The shell command itself.
    :var cwd: Working directory where the command would get run (if known).

    e.g.
        Command("calc.exe")
        Command("calc.exe", cwd=r"C:\Windows\System32")
    """
    value: str
    cwd: str = None

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        # Process generally uses a UUIDv4 but we want to deduplicate when the same command is used so we will use a v5
        identifier = "process--" + str(uuid.uuid5(self._STIX_NAMESPACE, f"{self.value}/{self.cwd}"))

        result = STIXResult(fixed_timestamp=fixed_timestamp)
        result.add_linked(stix.Process(command_line=self.value, cwd=self.cwd, id=identifier))
        result.create_tag_note(self, result.linked_stix[-1])
        return result

    def as_formatted_dict(self, flat=False) -> dict:
        return {
            "tags": self.tags,
            "command": self.value,
            "working_directory": self.cwd,
        }


@attr.s(**config)
class Credential(Metadata):
    """
    Collection of username and password used as credentials.

    e.g.
        Credential(username="admin", password="123456")
    """
    username: str = None
    password: str = None

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        
        params = {}
        if self.username:
            params["account_login"] = self.username

        if self.password:
            params["credential"] = self.password

            # the default UUIDv5 generation scheme for user-account does not factor in credentials so it is possible
            # to overwrite the same username with separate creds
            # since we do not want this with MWCP if a password is present will generate the ID in our own deterministic manner
            params["id"] = "user-account--" + str(uuid.uuid5(self._STIX_NAMESPACE, f"{self.username}//{self.password}"))

        result.add_linked(stix.UserAccount(**params))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


def Password(password: str) -> Credential:
    return Credential(password=password)


def Username(username: str) -> Credential:
    return Credential(username=username)


@attr.s(**config)
class CryptoAddress(Metadata):
    """
    A cryptocurrency address and its symbol.

    :param address: The address or unique identifier of the crypto wallet.
    :param symbol: A unique symbol for the cryptocurrency platform.
        This is usually the ticker symbol like "BTC", but can be something else more appropriate.

    e.g.
        # Sample address pulled from bitcoinwiki.org/wiki/Bitcoin_address
        CryptoAddress("14qViLJfdGaP4EeHnDyJbEGQysnCpwk3gd", "BTC")
    """
    address: str
    symbol: str = None

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        params = {
            "address": self.address
        }

        if self.symbol:
            params["currency_type"] = self.symbol.lower().replace(" ", "-")

        result.add_linked(stix_extensions.CryptoCurrencyAddress(**params))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


_ActionType = Union[Command, str]
_ActionType = Union[List[_ActionType], _ActionType]

def _action_converter(actions):
    # Convenience to allow users to pass in strings or a single command not in a list.
    if actions is not None:
        if not isinstance(actions, list):
            actions = [actions]
        actions = [
            Command(command) if isinstance(command, str) else command
            for command in actions
        ]
    return actions


@attr.s(**config)
class ScheduledTask(Metadata):
    """
    A Windows Scheduled task

    NOTE: This is currently only covers basic registration info and commands that get run.
        Other information such as trigger information is currently not captured.
        Please use 'Other' to store other information if desired.

    e.g.
        ScheduledTask("calc.exe", name="ActiveXServer")
        ScheduleTask([Command("calc.exe", cwd=r"C:\Temp"), Command("notepad.exe")], name="LegitWindowsTask")
    """
    # TODO: for now we are only accounting for command (Exec) actions.
    #   Add support for COM, email, and message types.
    actions: _ActionType = attr.ib(
        default=None,
        converter=_action_converter,
        metadata={"jsonschema": {
            "type": "array",
            "items": Command.schema(),
        }}
    )
    name: str = None
    description: str = None
    author: str = None
    credentials: Credential = None

    @classmethod
    def from_xml(cls, xml_data: str) -> "ScheduledTask":
        """
        Creates a ScheduledTask from exported xml file.

        Based on https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema
        """
        xml_data = xml_data.strip()
        # Remove namespace because it makes parsing complex.
        xml_data = re.sub(' xmlns="[^"]+"', '', xml_data, count=1)
        try:
            root = ElementTree.fromstring(xml_data)
        except ElementTree.ParseError as e:
            raise ValueError(f"Failed to parse XML data: {e}")
        if root.tag != "Task":
            raise ValueError(f"Expected root tag to be 'Task', got '{root.tag}'")

        # Parse registration info
        # NOTE: Must check with 'is None' because truthiness is still False with .find() for some reason.
        description = None
        author = None
        if (registration := root.find("RegistrationInfo")) is not None:
            if (description := registration.find("Description")) is not None:
                description = description.text
            if (author := registration.find("Author")) is not None:
                author = author.text

        # Parse commands.
        actions_meta = []
        if (actions := root.find("Actions")) is not None:
            for action in actions.findall("Exec"):
                command = action.find("Command")
                if command is None:
                    raise ValueError(f"Expected 'Command' tag.")
                command = command.text
                if (arguments := action.find("Arguments")) is not None:
                    command += " " + arguments.text
                if (cwd := action.find("WorkingDirectory")) is not None:
                    cwd = cwd.text
                actions_meta.append(Command(command, cwd=cwd))

        return cls(actions_meta, description=description, author=author)

    def as_formatted_dict(self, flat=False) -> dict:
        """
        Formatting in order to collapse the actions.

        TODO: Look into doing this generically for list fields.
        """
        tags = list(self.tags)
        if self.credentials:
            tags.extend(self.credentials.tags)

        actions = []
        if self.actions is not None:
            for action in self.actions:
                tags.extend(action.tags)
                if action.cwd:
                    actions.append(f"{action.cwd}> {action.value}")
                else:
                    actions.append(action.value)

        return {
            "tags": sorted(set(tags)),
            "actions": "\n".join(actions),
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "username": self.credentials.username if self.credentials else None,
            "password": self.credentials.password if self.credentials else None,
        }

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)

        params = {}
        if self.name:
            params["name"] = self.name
        if self.description:
            params["description"] = self.description
        if self.author:
            params["author"] = self.author
        if self.credentials:
            credentials = self.credentials.as_stix(base_object)
            result.merge_ref(credentials)
            params["user_account_ref"] = credentials.linked_stix[-1].id

        scheduled_task = stix_extensions.ScheduledTask(**params)
        result.add_linked(scheduled_task)
        result.create_tag_note(self, scheduled_task)

        for action in self.actions:
            action_obj = action.as_stix(base_object)
            result.merge(action_obj)
            result.add_unlinked(stix.Relationship(
                relationship_type="contained",
                source_ref=scheduled_task.id,
                target_ref=action_obj.linked_stix[-1].id,
                created=fixed_timestamp,
                modified=fixed_timestamp,
                allow_custom=True,
            ))

        return result


@attr.s(**config)
class Socket2(Metadata):
    """
    A collection of address, port, and protocol used together to make a socket
    connection.

    e.g.
        Socket(address="bad.com", port=21, protocol="tcp")
    """
    _VALID_PROTOCOLS = {"tcp", "udp", "icmp"}

    address: str = None  # ip address or domain  # TODO: should this be split up?
    port: int = attr.ib(
        default=None,
        metadata={"jsonschema": {
            "type": "integer",
            "minimum": 0,
            "maximum": 65535,
        }}
    )
    network_protocol: str = attr.ib(
        default=None,
        converter=lambda v: str(v).lower() if v is not None else v,
        metadata={"jsonschema": {
            "enum": sorted(_VALID_PROTOCOLS),
        }}
    )
    listen: bool = None

    @classmethod
    def _type(cls):
        return "socket"

    def __attrs_post_init__(self):
        # Add the _from_port attribute, used internally for backwards compatibility support.
        self._from_port = False

    @port.validator
    def _validate_port(self, attribute, value):
        if value is not None and not 0 <= value <= 65535:
            raise ValidationError(f"port must be between 0 and 65535. Got {value}")

    @network_protocol.validator
    def _validate_protocol(self, attribute, value):
        if value is not None and value not in self._VALID_PROTOCOLS:
            raise ValidationError(f"protocol {value} is not one of {sorted(self._VALID_PROTOCOLS)}")

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        # we define a static namespace explicitly for MWCP network traffic objects to ensure we deduplicate within MWCP
        # in general it is bad practice to deduplicate Network Traffic but as this is static analysis we want
        # to find correlation in a live environment this would be highly discouraged
        namespace = self._STIX_NAMESPACE

        result = STIXResult(fixed_timestamp=fixed_timestamp)
        network_values = {
            "is_active": False,
            "id": "network-traffic--" + str(uuid.uuid5(
                namespace,
                f"{self.address}//{self.port}//{self.network_protocol}//{self.listen}"
            ))
        }

        # Make an address object if this is present but add it to the list after the network traffic
        # for better malware analysis results
        address = None
        if self.address:
            address_type = self._guess_address_type(self.address)
            if address_type == "ipv6":
                network_values["dst_ref"] = stix.IPv6Address(value=self.address)
                network_values["protocols"] = ["ipv6"]
            elif address_type == "ipv4":
                network_values["dst_ref"] = stix.IPv4Address(value=self.address)
                network_values["protocols"] = ["ipv4"]
            else:
                network_values["dst_ref"] = stix.DomainName(value=self.address)
                # This is ultimately a guess, but it is safer to assume a domain maps
                # to ipv4 than ipv6, and we must pick one
                network_values["protocols"] = ["ipv4"]
        else:
            network_values["src_ref"] = stix.IPv4Address(value="0.0.0.0")
            network_values["protocols"] = ["ipv4"]

        # if a value was provided it should sit after ipv4 or ipv6 respectively
        if self.network_protocol:
            network_values["protocols"].append(self.network_protocol)

        if self.port is not None:
            if self.listen:
                network_values["src_port"] = self.port
            else:
                network_values["dst_port"] = self.port

        if "src_ref" in network_values:
            result.add_unlinked(network_values["src_ref"])
        else:
            result.add_unlinked(network_values["dst_ref"])

        traffic = stix.NetworkTraffic(**network_values)
        result.create_tag_note(self, traffic)

        # we want the network traffic to be the last object so it is always consistently placed
        result.add_linked(traffic)

        return result

    @staticmethod
    def _guess_address_type(address) -> str:
        """
        Used to see if an address is ipv4, ipv6, or a domain
        """
        # the fewest number of : in an ipv6 is for ::1.  A domain or IP should never have one so checking for 2 is safe
        if address.count(":") > 1:
            return "ipv6"

        # IPv4 must be 4 octets and no TLD can be a number so checking for both gives us a good guess between the two
        parts = address.split(".")
        if len(parts) == 4:
            if parts[3].isnumeric():
                if 0 <= int(parts[3]) < 256:
                    return "ipv4"

        return "domain"


def Socket(address=None, port=None, network_protocol=None, listen=None, c2=None) -> Socket2:
    socket = Socket2(address=address, port=port, network_protocol=network_protocol, listen=listen)
    if c2:
        socket.add_tag("c2")
    return socket


def SocketAddress(*args, **kwargs) -> Socket2:
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version. "
        "Please use Socket() instead.",
        DeprecationWarning
    )
    return Socket(*args, **kwargs)


def C2SocketAddress(address: str, port: int = None, protocol: str = None) -> Socket2:
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version",
        DeprecationWarning
    )
    socket = Socket(address=address, port=port, network_protocol=protocol)
    socket.add_tag("c2")
    return socket


def Port(port: int, protocol: str = None) -> Socket2:
    """
    TCP or UDP port.
    This generally refers to outbound connections where the malware is the client.
    Other network layer protocols, such as ICMP can be represented here.
    Application layer connections, such as HTTP, should be indicated by making a URL instead.
    """
    socket = Socket(port=port, network_protocol=protocol)
    socket._from_port = True
    return socket


def ListenPort(port: int, protocol: str = None) -> Socket2:
    socket = Socket(port=port, network_protocol=protocol, listen=True)
    socket._from_port = True
    return socket


def Address(address: str) -> Socket2:
    return Socket(address=address)


def C2Address(address: str) -> Socket2:
    socket = Socket(address=address)
    socket.add_tag("c2")
    return socket


@attr.s(**config)
class URL2(Metadata):
    """
    RFC 3986 URL

    e.g.
        URL("https://10.11.10.13:443/images/baner.jpg")
    """
    url: str = None
    path: str = None
    query: str = None
    protocol: str = None

    @classmethod
    def _type(cls):
        return "url"

    _URL_RE = re.compile(
        r"((?P<app_protocol>[a-z\.\-+]{1,40})://)?(?P<address>\[?[^/]+\]?)"
        r"(?P<path>/[^?]+)?(?P<query>.*)",
        flags=re.IGNORECASE
    )

    def __attrs_post_init__(self):
        self._processed = False  # prevent infinite loop.
        # Hidden fields for reporting later.
        self._socket = None
        self._credential = None

        if self.url:
            self._parse_url()

    def _parse_url(self):
        match = self._URL_RE.match(self.url)
        if not match:
            raise ValidationError(f"Error parsing as url: {self.url}")

        app_protocol = match.group("app_protocol") or None
        path = match.group("path") or None
        query = match.group("query") or None
        port = None

        address = match.group("address")
        if address:
            address = address.rstrip(": ")
            if address.startswith("["):
                # ipv6--something like
                # [fe80::20c:1234:5678:9abc]:80
                address, found, port = address[1:].partition("]:")
            else:
                address, found, port = address.partition(":")
            if found and not port:
                raise ValidationError(f"Invalid URL {self.url}, found ':' at end without a port.")
            elif not port:
                port = None

        if address or port:
            self._socket = Socket(address=address, port=port)
        # TODO: determine how to parse username, password from URL
        #if username or password:
        #    self._credential = Credential(username=username, password=password)

        if not self.path:
            self.path = path
        if not self.query:
            self.query = query
        if not self.protocol:
            self.protocol = app_protocol

    @property
    def socket(self) -> Optional[Socket2]:
        warnings.warn(
            "This function is a temporary getter. This may be removed in a future version. "
            "Please get from Network object instead.",
            DeprecationWarning
        )
        return self._socket or None

    @socket.setter
    def socket(self, value: Socket2):
        warnings.warn(
            "This function is a temporary setter. This may be removed in a future version. "
            "Please set with Network() instead.",
            DeprecationWarning
        )
        self._socket = value

    @property
    def credential(self) -> Optional[Credential]:
        warnings.warn(
            "This function is a temporary getter. This may be removed in a future version. "
            "Please get from Network object instead.",
            DeprecationWarning
        )
        return self._credential or None

    @credential.setter
    def credential(self, value: Credential):
        warnings.warn(
            "This function is a temporary setter. This may be removed in a future version. "
            "Please set with Network() instead.",
            DeprecationWarning
        )
        self._credential = value

    @property
    def c2(self) -> Optional[bool]:
        warnings.warn(
            "This function is a temporary getter. This may be removed in a future version. "
            "Please get from Socket2 object instead.",
            DeprecationWarning
        )
        return "c2" in self._socket.tags or "c2" in self.tags or None

    @c2.setter
    def c2(self, value: bool):
        warnings.warn(
            "This function is a temporary setter. This may be removed in a future version. "
            "Please set with Socket2() instead.",
            DeprecationWarning
        )
        # Add tag(s) if c2 == True
        if value:
            self.tags.append("c2")
            if self._socket:
                self._socket.tags.append("c2")

    def post_processing(self, report):
        """
        Creates a Network object if URL contains parsed out socket or credential information.
        """
        if not self._processed:
            self._processed = True
            if self._socket or self._credential:
                network = Network(url=self, socket=self._socket, credential=self._credential)
                # Move "c2" tag to network object if it exists.
                if "c2" in self.tags:
                    network.add_tag("c2")
                    if self._socket:
                        self._socket.add_tag("c2")
                report.add(network)

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)

        if not self.url:
            if self.path:   # TODO: determine if observedstring or url
                result.add_linked(stix_extensions.ObservedString(purpose="url-path", value=self.path))
            elif self.query:
                result.add_linked(stix_extensions.ObservedString(purpose="url-query", value=self.query))
            else:
                warnings.warn("Skipped creation of STIX string since the parser provided no URL data")
                return result
        else:
            result.add_linked(stix.URL(value=self.url))
        if self.protocol:
            protocol = self.protocol.upper()
            if protocol != "HTTP" and protocol != "HTTPS":
                result.add_unlinked(stix.Note(
                    labels=protocol,
                    content=protocol,
                    object_refs=[result.linked_stix[0].id],
                    created=fixed_timestamp,
                    modified=fixed_timestamp,
                    allow_custom=True
                ))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


@attr.s(**config)
class Network(Metadata):
    """
    A collection of URL, Socket and Credential to relate them together

    e.g. Network(
            url=metadata.URL2(url="https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
            socket=metadata.Socket(port=8080),
            credential=metadata.Credential(username="You", password="Tube")
        )
    """
    url: URL2 = None
    socket: Socket2 = None
    credential: Credential = None

    def __attrs_post_init__(self):
        if self.url and not self.url._processed:
            if not self.socket:
                self.socket = self.url._socket
            if not self.credential:
                self.credential = self.url._credential
            self.url._processed = True  # prevent URL2 from creating another Network object during postprocessing.
        if sum(map(bool, [self.url, self.socket, self.credential])) < 2:
            raise ValidationError(f"Network object must have at least 2 fields provided: {self!r}")

    def as_formatted_dict(self, flat=False) -> dict:
        sup = super().as_formatted_dict(flat=flat)
        # Fixup double "Url / Url" field.
        return {key.replace("url.url", "url"): value for (key, value) in sup.items()}

    def post_processing(self, report):
        if self.socket and "c2" in self.socket.tags:
            self.add_tag("c2")
            if self.url:
                self.url.add_tag("c2")

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        rels = []

        if self.url and any([self.url.url, self.url.path, self.url.query]):
            result.merge(self.url.as_stix(base_object, fixed_timestamp))

        if self.socket:
            result.merge(self.socket.as_stix(base_object, fixed_timestamp))
            if self.url and len(result.linked_stix) > 1:
                # Only add this relationship if a NetworkTraffic and URL both already exist in the linked_stix.
                # If the STIX URL object doesn't exist, no relationship needed
                rels.append({
                    "relationship_type" : "used",
                    "source_ref" : result.linked_stix[-1].id,
                    "target_ref": result.linked_stix[0].id,
                    "created": fixed_timestamp,
                    "modified": fixed_timestamp
                })
            elif self.url and self.url.protocol and not any([self.url.url, self.url.path, self.url.query]):
                protocol = self.url.protocol.upper()
                result.add_unlinked(stix.Note(
                    labels=protocol,
                    content=protocol,
                    object_refs=[result.linked_stix[0].id],
                    created=fixed_timestamp,
                    modified=fixed_timestamp,
                    allow_custom=True
                ))

        if self.credential:
            result.merge(self.credential.as_stix(base_object))
            if self.url or self.socket:
                rels.append({
                    "relationship_type": "contained",
                    "source_ref": result.linked_stix[0].id,
                    "target_ref": result.linked_stix[-1].id,
                    "created": fixed_timestamp,
                    "modified": fixed_timestamp
                })

        if len(rels) == 1:
            result.add_unlinked(stix.Relationship(**rels[0]))
        elif rels:
            # Add a label to both relationships which contain the ID not contained in either the source or target refs
            # i.e. with A -> B and B -> C, add C as a label to the first relationship and A as a label to the second
            rels[0]["labels"] = [result.linked_stix[2].id]
            rels[1]["labels"] = [result.linked_stix[1].id]
            result.add_unlinked(stix.Relationship(**rels[0]))
            result.add_unlinked(stix.Relationship(**rels[1]))
        return result


def URL(
    url: str = None,
    socket: Socket2 = None,
    path: str = None,
    query: str = None,
    application_protocol: str = None,
    credential: Credential = None
) -> URL2:
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version. "
        "Please use URL2() instead.",
        DeprecationWarning
    )
    url_obj = URL2(url=url, path=path, query=query, protocol=application_protocol)
    if socket:
        url_obj._socket = socket
    if credential:
        url_obj._credential = credential
    return url_obj


def C2URL(
        url: str = None,
        socket: Socket2 = None,
        path: str = None,
        query: str = None,
        application_protocol: str = None,
        credential: Credential = None
) -> URL2:
    url_obj = URL(
        url=url,
        path=path,
        query=query,
        application_protocol=application_protocol,
        socket=socket,
        credential=credential
    )
    url_obj.c2 = True
    return url_obj



def URLPath(path: str) -> URL2:
    """Path portion of URL"""
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version. "
        "Please use URL2() instead.",
        DeprecationWarning
    )
    return URL2(path=path)


def URLQuery(query: str) -> URL2:
    """Query portion of URL"""
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version. "
        "Please use URL() instead.",
        DeprecationWarning
    )
    return URL2(query=query)


def Proxy(
        username: str = None,
        password: str = None,
        address: str = None,
        port: int = None,
        protocol: str = None
) -> Union[Network, Socket, Credential]:
    """
    Generates URL object from given proxy connection information.

    e.g.
        Proxy(
            username="admin",
            password="pass",
            address="192.168.1.1",
            port=80,
            protocol="tcp",
        )
    """
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version. "
        "Please use URL2() instead.",
        DeprecationWarning
    )
    socket: Socket2 = None
    credential: Credential = None
    if address or port or protocol:
        socket = Socket(address=address, port=port, network_protocol=protocol)
    if username or password:
        credential = Credential(username=username, password=password)
    if not socket:
        raise ValidationError("Proxy should have at least one of: [address, port, protocol], none provided")
    socket.add_tag("proxy")
    if credential:
        return Network(socket=socket, credential=credential)
    return socket


def ProxySocketAddress(address: str, port: int = None, protocol: str = None) -> Socket2:
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version. "
        "Please use Proxy() instead.",
        DeprecationWarning
    )
    return Proxy(address=address, port=port, protocol=protocol)


def ProxyAddress(address: str) -> Socket2:
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version. "
        "Please use Proxy() instead.",
        DeprecationWarning
    )
    return Proxy(address=address)


def FTP(
        username: str = None,
        password: str = None,
        url: str = None,
        address: str = None,
        port: Port = None,
) -> Union[URL2, Network, Socket]:
    """
    Generates URL object from given FTP credentials and URL or address information.

    e.g.
        FTP(
            username="admin",
            password="pass",
            url="ftp://badhost.com:21",
        )
    """
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version",
        DeprecationWarning
    )
    if not url and not address:
        raise ValidationError("Must provide either url or address. Neither provided.")
    if url and address:
        raise ValidationError("Must provide either url or address. Both provided.")
    url_object = None
    socket = None
    if url:
        url_object = URL2(url=url, protocol="ftp")
    else:
        socket = Socket(address=address, port=port)
        url_object = URL2(protocol="ftp")
    if username or password:
        return Network(credential=Credential(username=username, password=password), url=url_object, socket=socket)
    return Network(url=url_object, socket=socket)

@attr.s(**config)
class EmailAddress(Metadata):
    """
    Email address

    e.g.
        EmailAddress("email@bad.com")
    """
    value: str = attr.ib(metadata={"jsonschema": {
        "type": "string",
        "format": "email",
    }})

    @value.validator
    def _validate(self, attribute, value):
        if "@" not in value:
            raise ValidationError(f"Email address should at least have a '@' character.")

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        result.add_linked(stix.EmailAddress(value=self.value))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


@attr.s(**config)
class Event(Metadata):
    """
    Event object

    e.g.
        Event("MicrosoftExit")
    """
    value: str

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        content = f"Event Name: {self.value}"

        if self.tags:
            content += f"\n    Event Name Tags: {', '.join(self.tags)}"

        return STIXResult(content)


def _uuid_convert(value):
    """
    Converts value into a uuid.UUID value (if not already).
    This is necessary because uuid.UUID can't handle being constructed twice.
    """
    try:
        if isinstance(value, str):
            return uuid.UUID(value)
        elif isinstance(value, bytes):
            return uuid.UUID(bytes=value)
        elif isinstance(value, int):
            return uuid.UUID(int=value)
        elif isinstance(value, uuid.UUID):
            return value
        else:
            raise ValidationError(f"Invalid UUID: {value}")
    except Exception as e:
        raise ValidationError(f"Invalid UUID: {e}")

# NOTE: We are not typing this as uuid.UUID because that has caused issues with serialization.
#   Validation occurs in the below function.
@attr.s(**config)
class UUID(Metadata):
    """
    A 128-bit number used to identify information, also referred to as a GUID.

    e.g.
        UUID("654e5cff-817c-4e3d-8b01-47a6f45ae09a")
    """
    value: uuid.UUID = attr.ib(converter=_uuid_convert, metadata={"jsonschema": {
        "type": "string",
        "format": "uuid",
    }})

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        result.add_linked(stix_extensions.ObservedString(purpose="uuid", value=self.value))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


GUID = UUID  # alias


@attr.s(**config)
class UUIDLegacy(Metadata):
    """
    Legacy version of UUID that doesn't validate or convert the uuid in order to ensure
    the original raw strings is displayed.

    WARNING: This should not be used in new code. Use UUID instead.
    """
    value: str

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        result.add_linked(stix_extensions.ObservedString(purpose="uuid", value=self.value))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


@attr.s(**config)
class InjectionProcess(Metadata):
    """
    Process into which malware is injected.
    Usually this is a process name but it may take other forms such as a filename of the executable.

    e.g.
        InjectionProcess("iexplore")
        InjectionProcess("svchost")
    """
    value: str

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        content = f"Injects Into: {self.value}"

        if self.tags:
            content += f"\n    Injects Into Tags: {', '.join(self.tags)}"

        return STIXResult(content)


@attr.s(**config)
class Interval(Metadata):
    """
    Time malware waits between beacons or other activity given in seconds.

    e.g.
        Interval(3.0)
        Interval(0.1)
    """
    value: float

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        content = f"Interval: {self.value}"

        if self.tags:
            content += f"\n    Interval Tags: {', '.join(self.tags)}"

        return STIXResult(content)


@attr.s(**config)
class IntervalLegacy(Metadata):
    """
    Legacy version of interval that uses a string type instead of float in order to preserve original
    display of the interval.
    This was done in order to ensure the decimal is either included or not depending on what the user provides.

    WARNING: This should not be used in new code!
    """
    value: str

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        content = f"Interval: {self.value}"

        if self.tags:
            content += f"\n    Interval Tags: {', '.join(self.tags)}"

        return STIXResult(content)


@attr.s(**config)
class EncryptionKey(Metadata):
    """
    Encryption, encoding, or obfuscation key.

    e.g.
        EncryptionKey(
            b"\x6d\x79\x72\x63\x34\x6b\x65\x79",
            algorithm="rc4",
        )
        EncryptionKey(
            b"\x6d\x79\x72\x63\x34\x6b\x65\x79",
            algorithm="aes",
            mode="ecb",
            iv=b"\x00\x00\x00\x00\x00\x00\x00\x01",
        )
    """
    key: bytes
    algorithm: str = None
    mode: str = None
    iv: bytes = None

    # Tests encodings in order by preference.
    TEST_ENCODINGS = [
        "ascii",
        "utf-32-be", "utf-32-le", "utf-16-be", "utf-16-le", "utf-8",  # General (utf-7 omitted)
    ]

    def __attrs_post_init__(self):
        # Determines if user passed in key is an encoded utf8 string.
        # (Used for backwards compatibility support.)
        self._legacy = False
        # Used to allow user to provide display encoding.
        self._encoding_set = False
        self._encoding = None

    def with_encoding(self, encoding: Optional[str], raise_error=False) -> "EncryptionKey":
        """
        Allows you to set the encoding to use when displayed in the text report.
        This can also be used to tell MWCP not to try to decode the key.

        e.g.
            metadata.EncryptionKey(b"hello").with_encoding("ascii")  # will ensure ascii is used when displayed in report.
            metadata.EncryptionKey(b"hello").with_encoding(None)  # won't display ascii representation in report.

        (If not provided, MWCP will do its best to guess the right encoding.)

        :param encoding: Encoding to use or None to not decode key in report.
        :param raise_error: Whether to raise a ValidationError if the given encoding would fail to decode the key.
            Defaults to ignoring the encoding otherwise.

        :raises ValidationError: If given encoding fails to decode key. (if raise_error is True)
        """
        if not (isinstance(encoding, str) or encoding is None):
            raise ValueError(f"Encoding must be string or None. Got {type(encoding)}")
        if encoding:
            try:
                self.key.decode(encoding)
            except UnicodeDecodeError:
                if raise_error:
                    raise ValidationError(f"Failed to decode key {self.key!r} with given encoding: {encoding}")
                else:
                    logger.warning(f"Failed to decode key {self.key!r} with given encoding: {encoding}. Ignoring...")
                    return self
        self._encoding = encoding
        self._encoding_set = True
        return self

    @staticmethod
    def _num_raw_bytes(string: str) -> int:
        """
        Returns the number of raw bytes found in the given unicode string
        """
        count = 0
        for char in string:
            char = char.encode("unicode-escape")
            count += char.startswith(b"\\x") + char.startswith(b"\\u") * 2
        return count

    def _detect_encoding(self) -> Optional[str]:
        """
        Attempts to determine if the key can be encoded as a string.

        :returns: Best guess encoding if successful.
        """
        # If user gave us the encoding, use that.
        if self._encoding_set:
            return self._encoding

        # NOTE: Much of this is taken from rugosa.detect_encoding()
        data = self.key
        best_score = len(data)  # lowest score is best
        best_code_page = None
        for code_page in self.TEST_ENCODINGS:
            try:
                output = data.decode(code_page)
                if not output.isprintable():
                    continue
            except UnicodeDecodeError:
                continue

            score = self._num_raw_bytes(output)
            if not best_code_page or score < best_score:
                best_score = score
                best_code_page = code_page

        return best_code_page

    def as_formatted_dict(self, flat=False) -> dict:
        # Convert key into hex number
        key = f"0x{self.key.hex()}"

        # Add context if encoding can be detected from key.
        if encoding := self._detect_encoding():
            key += f' ("{self.key.decode(encoding)}")'

        return {
            "tags": self.tags,
            "key": key,
            "algorithm": self.algorithm,
            "mode": self.mode,
            "iv": f"0x{self.iv.hex()}" if self.iv else None,
        }

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        params = {"key_hex": self.key.hex()}

        if self.algorithm:
            params["algorithm"] = self.algorithm

        if self.mode:
            params["mode"] = self.mode

        if self.iv:
            params["iv_hex"] = self.iv.hex()

        result = STIXResult(fixed_timestamp=fixed_timestamp)
        result.add_linked(stix_extensions.SymmetricEncryption(**params))
        result.create_tag_note(self, result.linked_stix[-1])

        return result


def EncryptionKeyLegacy(key: str) -> EncryptionKey:
    """
    Legacy version of 'key' field which takes a string value instead of bytes.
    """
    warnings.warn(
        "EncryptionKeyLegacy is only for backwards compatibility support. Please use EncryptionKey instead.",
        DeprecationWarning
    )
    encryption_key = EncryptionKey(key.encode("utf-8")).with_encoding("utf-8")
    encryption_key._legacy = True
    return encryption_key


@attr.s(**config)
class DecodedString(Metadata):
    """
    Extracted decrypted or decoded string.

    e.g.
        DecodedString("badman")
        DecodedString("evilstring", encryption_key=EncryptionKey(b"secret", algorithm="xor"))
    """
    value: str
    encryption_key: EncryptionKey = None

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)

        # sometimes empty strings come up, so we should just discard these
        if not self.value:
            return result

        cur = stix_extensions.ObservedString(purpose="decoded", value=self.value)
        result.add_linked(cur)
        result.create_tag_note(self, cur)

        if self.encryption_key:
            sub = self.encryption_key.as_stix(base_object)
            result.merge(sub)
            result.add_unlinked(stix.Relationship(
                relationship_type="outputs",
                source_ref=sub.linked_stix[0].id,
                target_ref=cur.id,
                allow_custom=True,
                created=fixed_timestamp,
                modified=fixed_timestamp
            ))

        return result


@attr.s(**config)
class MissionID(Metadata):
    """
    Attacker specified identifier encoded in malware,
    usually reflected in beacons and often related to target or time of attack.

    e.g.
        MissionID("target4")
        MissionID("201412")
    """
    value: str

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        result.add_linked(stix_extensions.ObservedString(purpose="mission-id", value=self.value))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


@attr.s(**config)
class Mutex(Metadata):
    """
    Mutex name used to prevent multiple executions of malware

    e.g.
        Mutex("ithinkimalonenow")
        Mutex("0036a8117afa")
    """
    value: str

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        result.add_linked(stix.Mutex(name=self.value))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


@attr.s(**config)
class Other(Metadata):
    """
    All other items that don't fit within the existing declared schema.
    Value type is determined by the "value_format" property.

    e.g.
        Other("keylogger", True)
        Other("custom_info", b"\xde\xad\xbe\xef")
        Other("custom_info2", "hello")
    """
    key: str
    value: Union[int, bytes, str, bool]
    value_format: str = attr.ib(
        init=False,
        metadata={"jsonschema": {
            "enum": ["string", "bytes", "integer", "boolean"],
        }}
    )

    def __attrs_post_init__(self):
        if isinstance(self.value, bool):
            self.value_format = "boolean"
        elif isinstance(self.value, int):
            self.value_format = "integer"
        elif isinstance(self.value, str):
            self.value_format = "string"
        elif isinstance(self.value, bytes):
            self.value_format = "bytes"
        else:
            raise ValidationError(f"Got unexpected data: {self.value}")

    @classmethod
    def _structure(cls, value_dict: dict) -> Element:
        # Pull value_format to know how to decode value.
        value_format = value_dict.pop("value_format")
        value = value_dict["value"]
        if value_format == "bytes" and not isinstance(value, bytes):
            value = base64.b64decode(value)
        value_dict["value"] = value
        return super()._structure(value_dict)

    def as_formatted_dict(self, flat=False) -> dict:
        ret = super().as_formatted_dict()
        # Don't show value_format.
        del ret["value_format"]
        return ret

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        # boolean values and numbers should be appended as a single master Note instead of using this mechanism
        if self.value_format in ("boolean", "integer") or self.value in (b"", ""):
            content = f"{self.key}: {self.value}"

            if self.tags:
                content += f"\n    {self.key} Tags: {', '.join(self.tags)}"

            result = STIXResult(content)
        else:
            content = {
                "purpose": self.key.replace("_", "-").replace(" ", "-").lower(),
                "value": self.value
            }

            result = STIXResult(fixed_timestamp=fixed_timestamp)
            result.add_linked(stix_extensions.ObservedString(**content))
            result.create_tag_note(self, result.linked_stix[-1])

        return result


@attr.s(**config)
class Pipe(Metadata):
    r"""
    Named, one-way or duplex pipe for communication between the pipe server and one or more pipe clients.

    e.g.
        Pipe("\\.\\pipe\\namedpipe")
    """
    value: str

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        result.add_linked(stix_extensions.ObservedString(purpose="pipe", value=self.value))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


class RegistryHive(IntEnum):
    HKEY_CLASSES_ROOT = 0x80000000
    HKEY_CURRENT_USER = 0x80000001
    HKEY_LOCAL_MACHINE = 0x80000002
    HKEY_USERS = 0x80000003
    HKEY_PERFORMANCE_DATA = 0x80000004
    HKEY_CURRENT_CONFIG = 0x80000005
    HKEY_DYN_DATA = 0x80000006
    HKEY_CURRENT_USER_LOCAL_SETTINGS = 0x80000007
    HKEY_PERFORMANCE_TEXT = 0x80000050
    HKEY_PERFORMANCE_NLSTEXT = 0x80000060

    # Aliases
    HKCR = HKEY_CLASSES_ROOT
    HKCU = HKEY_CURRENT_USER
    HKLM = HKEY_LOCAL_MACHINE
    HKU = HKEY_USERS
    HKPD = HKEY_PERFORMANCE_DATA
    HKCC = HKEY_CURRENT_CONFIG
    HKDD = HKEY_DYN_DATA
    HKCULS = HKEY_CURRENT_USER_LOCAL_SETTINGS
    HKPT = HKEY_PERFORMANCE_TEXT
    HKPN = HKEY_PERFORMANCE_NLSTEXT


class RegistryDataType(IntEnum):
    """Registry value data types in winreg.h"""
    REG_NONE = 0
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_DWORD_LITTLE_ENDIAN = REG_DWORD
    REG_DWORD_BIG_ENDIAN = 5
    REG_LINK = 6
    REG_MULTI_SZ = 7
    REG_QWORD = 11


@attr.s(**config)
class Registry2(Metadata):
    """
    Registry key, value (or name), and data.
    (see docs.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry)

    e.g.
        Registry2(
            hive="HKLM",  # or metadata.RegistryHive.HKEY_LOCAL_MACHINE
            subkey="Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            value="Updater",
            data="c:\\update.exe"
        )
    """
    hive: RegistryHive = None
    subkey: str = None
    value: str = None  # registry key, value name, combination of the two
    data: Union[bytes, str, int, List[str]] = attr.ib(default=None)
    data_type: RegistryDataType = None

    def __attrs_post_init__(self):
        # Pull out hive if it was included in subkey.
        if not self.hive and self.subkey:
            hive, _, subkey = self.subkey.partition("\\")
            try:
                self.hive = RegistryHive[hive.upper()]
            except KeyError:
                pass
            else:
                self.subkey = subkey

        # Strip off leading or trailing \'s on subkey.
        if self.subkey:
            self.subkey = self.subkey.strip("\\")

        # Automatically set data type for some data values.
        if self.data_type is None and self.data is not None:
            if isinstance(self.data, str):
                # If we have more than one "\0", this is a string list.
                if self.data.count("\0") > 1:
                    self.data_type = RegistryDataType.REG_MULTI_SZ
                else:
                    self.data_type = RegistryDataType.REG_SZ
            elif isinstance(self.data, list) and all(isinstance(entry, str) for entry in self.data):
                self.data_type = RegistryDataType.REG_MULTI_SZ
            elif isinstance(self.data, bytes):
                self.data_type = RegistryDataType.REG_BINARY
            elif isinstance(self.data, int):
                if self.data <= 0xffffffff:
                    self.data_type = RegistryDataType.REG_DWORD
                else:
                    self.data_type = RegistryDataType.REG_QWORD
            # NOTE: We are not going to convert a data of None to be type REG_NONE because data could
            #   not be provided because we couldn't obtain it.
            #   User must explicitly set data_type to REG_NONE if it is known to be None.

        # Auto convert data set as REG_MULTI_SZ if given as a full string with null-terminations.
        if self.data_type == RegistryDataType.REG_MULTI_SZ and isinstance(self.data, str) and "\0" in self.data:
            if self.data.endswith("\0"):
                self.data = self.data[:-1]
            self.data = self.data.split("\0")

        # Strip off null termination for strings.
        if self.data and self.data_type == RegistryDataType.REG_SZ:
            self.data = self.data.rstrip("\0")

    @data.validator
    def _validate_data(self, attribute, value):
        if isinstance(value, int) and value < 0:
            raise ValidationError(f"Integer data value must be positive. Got {value}")

    @classmethod
    def _type(cls):
        return "registry"

    @classmethod
    def from_path(cls, path: str, data: Union[bytes, str, int] = None) -> "Registry2":
        """
        Generates a Registry from a given full path.
        The last segment of the path is assumed to be the value.
        """
        # Cast path to string to be more backwards compatible.
        if isinstance(path, bytes):
            path = path.decode("utf8")
        subkey, _, value = path.rpartition("\\")
        return Registry2(subkey=subkey or None, value=value or None, data=data)

    @property
    def key(self) -> Optional[str]:
        """
        The combination of the hive + subkey.
        """
        hive_name = self.hive.name if self.hive is not None else ""
        if hive_name or self.subkey:
            return "\\".join([hive_name, self.subkey or ""])
        else:
            return None

    def as_formatted_dict(self, flat=False) -> dict:
        return {
            "tags": self.tags,
            "key": self.key,
            "value": self.value,
            "data": self.data,
            "data_type": self.data_type.name if self.data_type is not None else None,
        }

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        value = {}
        properties = {}

        if self.key:
            properties["key"] = self.key

        if self.value:
            value["data"] = self.value

        if self.data_type:
            value["data_type"] = self.data_type.name

        if value:
            properties["values"] = [value]

        result.add_linked(stix.WindowsRegistryKey(**properties))
        result.create_tag_note(self, result.linked_stix[-1])

        return result


def Registry(path: str = None, key: str = None, value: str = None, data: Union[bytes, str, int] = None) -> Registry2:
    """
    Registry key and value.

    e.g.
        Registry(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            data="c:\\update.exe",
        )
    """
    warnings.warn(
        "Registry has been renamed to Registry2 during a transitional period to a new version of Registry " 
        "with a new signature. "
        "Please update to use Registry2 with explicit key/value fields or use the .from_path() constructor. "
        "NOTE: In a future version, once this function is deprecated, Registry2 will be renamed back to Registry "
        "using the new signature.",
        DeprecationWarning
    )
    if path is not None:
        registry = Registry2.from_path(path, data=data)
        # Need to overwrite key and value if provided in order to replicate legacy logic.
        if key:
            registry.subkey = key
        if value:
            registry.value = value
        return registry
    else:
        return Registry2(subkey=key, value=value, data=data)


def RegistryData(data: str) -> Registry2:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Registry() instead.", DeprecationWarning
    )
    return Registry2(data=data)


def RegistryPath(path: str) -> Registry2:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Registry() instead.", DeprecationWarning
    )
    return Registry2.from_path(path)


def RegistryPathData(path: str, data: str) -> Registry2:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Registry() instead.", DeprecationWarning
    )
    return Registry2.from_path(path, data=data)


def _int_dump(value: int) -> str:
    """
    Dumps integer into hex format in same style used by openssl.
    """
    # Display smaller values as decimal with hex in parenthesis.
    if value < (0x1 << (15 * 8)):
        return f"{value} ({hex(value)})"
    # Otherwise display as hex dump with bytes separated by ":"
    value_bytes = value.to_bytes((value.bit_length() + 7) // 8, "big")
    hex_dump = ":".join(f"{byte:02x}" for byte in value_bytes)
    hex_dump = textwrap.fill(hex_dump, width=45)
    return hex_dump


def _parse_rsa_xml(data: str):
    """
    Parses RSA key data from XML notation.
    Logs any errors as warnings.

    :raises ValueError: If nothing could be parsed out.
    """
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as e:
        raise ValueError(f"Failed to parse XML data: {e}")
    if root.tag != "RSAKeyValue":
        raise ValueError(f"Expected root tag to be 'RSAKeyValue', got '{root.tag}'")
    fields = {}
    for child in root:
        try:
            fields[child.tag] = int.from_bytes(base64.b64decode(child.text), byteorder="big")
        except binascii.Error as e:
            logger.warning(f"Failed to base64 decode data in '{child.tag}': '{child.text}' with error: {e}")

    if not fields:
        raise ValueError(f"Failed to parse any RSA key data from XML.")

    return fields


@attr.s(**config)
class RSAPrivateKey(Metadata):
    """
    RSA private key containing: public exponent, modulus, private exponent (d),
        p, q, d mod (p-1), d mod (q-1), q inv mod p
    """
    public_exponent: int = None
    modulus: int = None
    private_exponent: int = None
    p: int = None
    q: int = None
    d_mod_p1: int = None
    d_mod_q1: int = None
    q_inv_mod_p: int = None

    @classmethod
    def from_DER(cls, data: bytes) -> "RSAPrivateKey":
        """
        Generates RSAPrivateKey from data in ASN.1 DER format.

        :param data: RSA key data in ASN.1 DER format

        :raises ValueError: on failure
        """
        try:
            privkey, _ = asn1_decoder.decode(data, asn1Spec=rfc2437.RSAPrivateKey())
            return RSAPrivateKey(
                public_exponent=int(privkey.getComponentByName("publicExponent")),
                modulus=int(privkey.getComponentByName("modulus")),
                private_exponent=int(privkey.getComponentByName("privateExponent")),
                p=int(privkey.getComponentByName("prime1")),
                q=int(privkey.getComponentByName("prime2")),
                d_mod_p1=int(privkey.getComponentByName("exponent1")),
                d_mod_q1=int(privkey.getComponentByName("exponent2")),
                q_inv_mod_p=int(privkey.getComponentByName("coefficient")),
            )
        except PyAsn1Error as e:
            raise ValueError(f"Failed to extract RSA public key: {e}")

    @classmethod
    def from_PEM(
            cls, data: str,
            start_marker="-----BEGIN RSA PRIVATE KEY-----",
            end_marker="-----END RSA PRIVATE KEY-----"
    ) -> "RSAPrivateKey":
        """
        Generates RSAPrivateKey from data in ASN.1 PEM format.

        :param data: RSA key data in ASN.1 PEM format
        :param start_marker: Marks the beginning of the private key in PEM format.
        :param end_marker: Marks the end of the private key in PEM format.

        :raises ValueError: on failure
        """
        with io.StringIO(data) as fo:
            der = pem.readPemFromFile(fo, startMarker=start_marker, endMarker=end_marker)
            return cls.from_DER(der)

    @classmethod
    def from_BLOB(cls, data: bytes) -> "RSAPrivateKey":
        """
        Generates RSAPrivateKey from data stored in a Microsoft PRIVATEKEYBLOB format.

        :param data: RSA key data in Microsoft Blob format

        :raises ValueError: on failure
        """
        try:
            privkey = construct.PRIVATEKEYBLOB.parse(data)
            return RSAPrivateKey(
                public_exponent=privkey.pubexponent,
                modulus=privkey.modulus,
                private_exponent=privkey.D,
                p=privkey.P,
                q=privkey.Q,
                d_mod_p1=privkey.Dp,
                d_mod_q1=privkey.Dq,
                q_inv_mod_p=privkey.Iq,
            )
        except construct.ConstructError as e:
            raise ValueError(f"Failed to parse Private Key BLOB: {e}")

    @classmethod
    def from_XML(cls, data: str, fallback=False) -> Union["RSAPrivateKey", "RSAPublicKey"]:
        """
        Generates RSAPrivateKey from data stored in serialized .NET XML resource.
        (see RSA.FromXMLString() from .NET API documentation)

        :param data: .NET Microsoft XML resource data
        :param fallback: Whether to fallback to creating a RSAPublicKey if only the public exponent and modulus exists.
            (useful if you don't know/care if the XML data contains a public or private key)

        :raises ValueError: on failure
        """
        fields = _parse_rsa_xml(data)
        if fallback and not any(key in fields for key in ("D", "P", "Q", "DP", "DQ", "InverseQ")):
            return RSAPublicKey.from_XML(data)
        return RSAPrivateKey(
            public_exponent=fields.get("Exponent", None),
            modulus=fields.get("Modulus", None),
            private_exponent=fields.get("D", None),
            p=fields.get("P", None),
            q=fields.get("Q", None),
            d_mod_p1=fields.get("DP", None),
            d_mod_q1=fields.get("DQ", None),
            q_inv_mod_p=fields.get("InverseQ", None),
        )

    def as_formatted_dict(self, flat=False) -> dict:
        """
        Display of RSAPrivateKey tends to create really wide output.
        Reformatting results to equivalent output you would get with:
            `openssl rsa -in key.pem -text -noout`
        """
        # NOTE: Not using openssl's field names since they are less descriptive.
        fields = [
            ("Modulus (n)", self.modulus),
            ("Public Exponent (e)", self.public_exponent),
            ("Private Exponent (d)", self.private_exponent),
            ("p", self.p),
            ("q", self.q),
            ("d mod (p-1)", self.d_mod_p1),
            ("d mod (q-1)", self.d_mod_q1),
            ("(inverse of q) mod p", self.q_inv_mod_p),
        ]

        value = ""
        for field, _value in fields:
            if _value is not None:
                value += f"{field}:\n{textwrap.indent(_int_dump(_value), '    ')}\n"

        return {"tags": self.tags, "value": value or None}

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)

        # x509 specifies hashes and serial for deterministic IDs in most cases, but we will never have that
        # As such we are using our own namespace to generate a deterministic ID instead of forcing it to be a UUIDv4
        # We only use the properties for the public key to make this ID so that we can avoid duplicating the
        # public + private key data when both are present
        namespace = self._STIX_NAMESPACE
        params = {
            "id": "x509-certificate--" + str(uuid.uuid5(namespace, f"{self.public_exponent}//{self.modulus}"))
        }

        if self.public_exponent:
            params["subject_public_key_exponent"] = self.public_exponent

        if self.modulus:
            params["subject_public_key_modulus"] = str(self.modulus)

        extensions = stix_extensions.rsa_private_key_extension(
            self.private_exponent, self.p, self.q, self.d_mod_p1, self.d_mod_q1, self.q_inv_mod_p
        )

        if extensions:
            params["extensions"] = extensions

        result.add_linked(stix.X509Certificate(**params))
        result.create_tag_note(self, result.linked_stix[-1])

        return result


@attr.s(**config)
class RSAPublicKey(Metadata):
    """
    RSA public key containing: public_exponent, modulus
    """
    public_exponent: int = None
    modulus: int = None

    @classmethod
    def from_DER(cls, data: bytes) -> "RSAPublicKey":
        """
        Generates RSAPublicKey from data in ASN.1 DER format.

        :param data: RSA key data in ASN.1 DER format

        :raises ValueError: on failure
        """
        try:
            keyinfo, _ = asn1_decoder.decode(data, asn1Spec=rfc2459.SubjectPublicKeyInfo())
            pubkey_obj = keyinfo.getComponentByName("subjectPublicKey")
            key_data = bitarray(pubkey_obj.asBinary()).tobytes()
            pubkey, _ = asn1_decoder.decode(key_data, asn1Spec=rfc2437.RSAPublicKey())
            return RSAPublicKey(
                public_exponent=int(pubkey.getComponentByName("publicExponent")),
                modulus=int(pubkey.getComponentByName("modulus")),
            )
        except PyAsn1Error as e:
            raise ValueError(f"Failed to extract RSA public key: {e}")

    @classmethod
    def from_PEM(
            cls, data: str,
            start_marker="-----BEGIN PUBLIC KEY-----",
            end_marker="-----END PUBLIC KEY-----"
    ) -> "RSAPublicKey":
        """
        Generates RSAPublicKey from data in ASN.1 PEM format.

        :param data: RSA key data in ASN.1 PEM format
        :param start_marker: Marks the beginning of the public key in PEM format.
        :param end_marker: Marks the end of the public key in PEM format.

        :raises ValueError: on failure
        """
        with io.StringIO(data) as fo:
            der = pem.readPemFromFile(fo, startMarker=start_marker, endMarker=end_marker)
            return cls.from_DER(der)

    @classmethod
    def from_BLOB(cls, data: bytes) -> "RSAPublicKey":
        """
        Generates RSAPublicKey from data stored in a Microsoft PUBLICKEYBLOB format.

        :param data: RSA key data in Microsoft Blob format

        :raises ValueError: on failure
        """
        try:
            pubkey = construct.PUBLICKEYBLOB.parse(data)
            return RSAPublicKey(
                public_exponent=pubkey.pubexponent,
                modulus=pubkey.modulus,
            )
        except construct.ConstructError as e:
            raise ValueError(f"Failed to parse Public Key BLOB: {e}")

    @classmethod
    def from_XML(cls, data: str) -> "RSAPublicKey":
        """
        Generates RSAPublicKey from data stored in serialized .NET XML resource.
        (see RSA.FromXMLString() from .NET API documentation)

        :param data: .NET Microsoft XML resource data

        :raises ValueError: on failure
        """
        fields = _parse_rsa_xml(data)
        return RSAPublicKey(
            public_exponent=fields.get("Exponent", None),
            modulus=fields.get("Modulus", None),
        )

    def as_formatted_dict(self, flat=False) -> dict:
        """
        Display of RSAPublicKey tends to create really wide output.
        Reformatting results to equivalent output you would get with:
            `openssl rsa -in key.pem -text -noout -pubin`
        """
        fields = [
            ("Modulus (n)", self.modulus),
            ("Public Exponent (e)", self.public_exponent),
        ]

        value = ""
        for field, _value in fields:
            if _value is not None:
                value += f"{field}:\n{textwrap.indent(_int_dump(_value), '    ')}\n"

        return {"tags": self.tags, "value": value or None}

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)

        # x509 specifies hashes and serial for deterministic IDs in most cases, but we will never have that
        # As such we are using our own namespace to generate a deterministic ID instead of forcing it to be a UUIDv4
        namespace = self._STIX_NAMESPACE
        params = {
            "id": "x509-certificate--" + str(uuid.uuid5(namespace, f"{self.public_exponent}//{self.modulus}"))
        }

        if self.public_exponent:
            params["subject_public_key_exponent"] = self.public_exponent

        if self.modulus:
            params["subject_public_key_modulus"] = str(self.modulus)

        result.add_linked(stix.X509Certificate(**params))
        result.create_tag_note(self, result.linked_stix[-1])

        return result


@attr.s(**config)
class Service(Metadata):
    r"""
    Windows service information

    :var name: The name of the service (lpServiceName)
    :var display_name: The display name to be used by user interface programs to identify the service. (lpDisplayName)
    :var description: The description of the service. (lpDescription)
    :var image: The fully qualified path to the service binary file. (lpBinaryPathName)
        Path can also include arguments e.g. "d:\myshare\myservice.exe arg1 arg2"
    :var dll: Path to DLL file used by service, if any.

    e.g.
        Service(
            name="WindowsUserManagement",
            display_name="Windows User Management",
            description="Provides a common management to access information about windows user."
            image="%System%\\svohost.exe"
        )
    """
    name: str = None
    display_name: str = None
    description: str = None
    image: str = None
    dll: str = None

    def post_processing(self, report):
        """Add file path in image field to report as a file path."""
        # we use tactic of looking for first .exe in value. This is
        # not guaranteed to be reliable
        # TODO: This is here just to keep legacy logic. Determine if this is still appropriate when we remove
        #   deprecations.
        if self.image and ".exe" in self.image:
            report.add(FilePath(self.image[:self.image.find(".exe") + 4]))
        # TODO: doing this over setting dll as a Path type so we can set it as a "FilePath"
        if self.dll:
            report.add(FilePath(self.dll))

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        # Process generally uses a UUIDv4 but we want to deduplicate when the same command is used so we will use a v5
        namespace = self._STIX_NAMESPACE

        result = STIXResult(fixed_timestamp=fixed_timestamp)
        params = {
            "id": "process--" + str(uuid.uuid5(
                namespace, f"{self.image}/{self.name}/{self.display_name}/{self.description}/{self.image}/{self.dll}"
            ))
        }
        extension = {}

        if self.name:
            extension["service_name"] = self.name

        if self.display_name:
            extension["display_name"] = self.display_name

        if self.description:
            extension["descriptions"] = [self.description]

        if self.image:
            params["command_line"] = self.image

        if self.dll and self.dll != self.image:
            dir_path = str(pathlib.Path(self.dll).parent)

            if dir_path:
                result.add_unlinked(stix.Directory(path=dir_path))
                result.add_unlinked(stix.File(name=self.image, parent_directory_ref=result.unlinked_stix[-1].id))
                params["image_ref"] = result.unlinked_stix[-1].id

        if extension:
            params["extensions"] = {"windows-service-ext": extension}

        result.add_linked(stix.Process(**params))
        result.create_tag_note(self, result.linked_stix[-1])

        return result


def ServiceName(name: str) -> Service:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Service() instead.", DeprecationWarning
    )
    return Service(name=name)


def ServiceDescription(description: str) -> Service:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Service() instead.", DeprecationWarning
    )
    return Service(description=description)


def ServiceDisplayName(display_name: str) -> Service:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Service() instead.", DeprecationWarning
    )
    return Service(display_name=display_name)


def ServiceDLL(dll: str) -> Service:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Service() instead.", DeprecationWarning
    )
    return Service(dll=dll)


def ServiceImage(image: str) -> Service:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Service() instead.", DeprecationWarning
    )
    return Service(image=image)


@attr.s(**config)
class SSLCertSHA1(Metadata):
    """
    SSL Certificate SHA-1 Hash

    e.g.
        SSLCertSHA1("c29d79df9b5416fd416c31e57cd525dfc23a8f66")
    """
    value: str = attr.ib(metadata={"jsonschema": {
        "type": "string",
        "pattern": "^[0-9a-fA-F]{40}$",
    }})

    _SHA1_RE = re.compile("[0-9a-fA-F]{40}")

    @value.validator
    def _validate(self, attribute, value):
        if not self._SHA1_RE.match(value):
            raise ValidationError(f"Invalid SHA1 hash found: {value!r}")

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        result.add_linked(stix.X509Certificate(hashes={"SHA-1": self.value}))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


@attr.s(**config)
class UserAgent(Metadata):
    """
    Software identifier used by malware

    e.g.
        UserAgent("Mozilla/4.0 (compatible; MISE 6.0; Windows NT 5.2)")
    """
    value: str

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        result = STIXResult(fixed_timestamp=fixed_timestamp)
        result.add_linked(stix_extensions.ObservedString(purpose="user-agent", value=self.value))
        result.create_tag_note(self, result.linked_stix[-1])
        return result


@attr.s(**config)
class Version(Metadata):
    """
    The version of the malware.
    To the degree possible this should be based directly on artifacts from the malware.

    e.g.
        Version("3.1")
        Version("incrementing XOR encoding")
    """
    value: str

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        content = f"Version: {self.value}"

        if self.tags:
            content += f"\n    Version: {', '.join(self.tags)}"

        return STIXResult(content)


@attr.s(**config)
class File(Metadata):
    """
    Represents a file, which is either the original input file, a file dispatched by the parser,
    or a supplemental file generated by the parser

    :var name: Name of the file.
    :var description: Description of the file.
    :var md5: MD5 hash of the file represented as a hex string.
    :var sha1: SHA1 hash of the file represented as a hex string.
    :var sha256: SHA256 hash of the file represented as a hex string.
    :var architecture: Type of architecture of the file (if applicable)
    :var compile_time: UTC Timestamp the file was compiled as reported (if applicable)
    :var file_path: Path where the file exists or has been written out to on the local file system.
    :var data: Raw bytes of the file.
    :var derivation: Description of how the file was obtained or its categorization.
        e.g. "decrypted", "deobfuscated", "supplemental"
    """
    name: str = None
    description: str = None
    md5: str = attr.ib(default=None)
    sha1: str = attr.ib(default=None)
    sha256: str = attr.ib(default=None)
    architecture: str = None
    compile_time: str = attr.ib(default=None, metadata={"jsonschema": {
        "type": "string",
        "format": "date-time",
    }})
    file_path: str = None
    data: bytes = None
    derivation: str = None

    def __attrs_post_init__(self):
        if self.data is not None:
            if not self.md5:
                self.md5 = hashlib.md5(self.data).hexdigest()
            if not self.sha1:
                self.sha1 = hashlib.sha1(self.data).hexdigest()
            if not self.sha256:
                self.sha256 = hashlib.sha256(self.data).hexdigest()

    # TODO: Add validation for hashes.

    def as_stix(self, base_object, fixed_timestamp=None) -> STIXResult:
        hashes = {}
        result = STIXResult(fixed_timestamp=fixed_timestamp)

        if self.md5:
            hashes["MD5"] = self.md5
        if self.sha1:
            hashes["SHA-1"] = self.sha1
        if self.sha1:
            hashes["SHA-256"] = self.sha256

        params = {
            "name": self.name,
            "hashes": hashes
        }

        if self.data:
            result.add_unlinked(stix.Artifact(payload_bin=base64.b64encode(self.data)))
            params["content_ref"] = result.unlinked_stix[0].id

        result.add_linked(stix.File(**params))

        # description is skipped because that is added to the malware-analysis that is later built for the
        # file by the report writer

        if self.compile_time or self.architecture:
            result.note_content = f"Compiled on: {self.compile_time}\nFor architecture: {self.architecture}"

        result.note_labels = self.tags

        return result

    @classmethod
    def from_file_object(cls, file_object):
        return cls(
            name=file_object.name,
            description=file_object.description,
            md5=file_object.md5,
            sha1=file_object.sha1,
            sha256=file_object.sha256,
            architecture=file_object.architecture,
            compile_time=file_object.compile_time.isoformat() if file_object.compile_time else None,
            # TODO: Update this when .file_path deprecation is removed.
            file_path=file_object.file_path if file_object._exists else None,
            data=file_object.data,
            derivation=file_object.derivation,
        ).add_tag(*file_object.tags)


# Helper aliases
InputFile = File  # Original input malware file that triggered parsing.
ResidualFile = File  # Relevant or related file created during parsing of malware.


def SupplementalFile(
        name: str = None,
        description: str = None,
        md5: str = None,
        sha1: str = None,
        sha256: str = None,
        architecture: str = None,
        compile_time: str = None,
        file_path: str = None,
        data: bytes = None
) -> File:
    """
    Helper function for creating a file that supplements the malware sample but isn't
    something obtained from the sample.
    e.g. string dump, annotated IDB, etc.
    """
    return File(
        name=name,
        description=description,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        architecture=architecture,
        compile_time=compile_time,
        file_path=file_path,
        data=data,
        derivation="supplemental",
    )


@attr.s(**config)
class Report(Element):
    """
    Defines the report of all metadata elements.

    :var mwcp_version: The version of MWCP used.
    :var input_file: The initial file processed.
    :var parser: The initial parser used to process the file.
    :var recursive: Whether parser recursively handled unidentified files using YARA matching.
    :var external_knowledge: External information provided by the user to assist the parser.
    :var errors: List of error messages that have occurred.
    :var logs: List of all log messages that have occurred.
    :var metadata: List of extracted metadata elements.
    """
    mwcp_version: str = attr.ib(init=False, factory=lambda: mwcp.__version__)
    input_file: File = None
    parser: str = None
    recursive: bool = False
    external_knowledge: Dict[str, Union[int, bool, str]] = attr.ib(
        factory=dict,
        metadata={"jsonschema": {
            "type": "object",
            "additionalProperties": {"type": ["integer", "boolean", "string"]},
        }}
    )
    errors: List[str] = attr.ib(factory=list)
    logs: List[str] = attr.ib(factory=list)
    metadata: List[Metadata] = attr.ib(factory=list)


@attr.s(**config)
class StringReport(Element):
    """
    Defines a report of decoded strings for a file.
    """
    file: File
    strings: List[DecodedString] = attr.ib(factory=list)

