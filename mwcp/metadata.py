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
from typing import Any, Union, List, Optional, TypeVar, Type, Set, Iterable

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

    # cattr doesn't handle Unions very nicely, so we'll recursively
    # handle the innards of Union types instead.
    # NOTE: Based on documentation, the cattr devs will eventually provide
    # better support for Unions in the future.
    if hasattr(type_, "__origin__") and type_.__origin__ is Union:
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
                    new_dict["tags"].append(tags)
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
    def _type(cls):
        """This function is used to determine name identifier for the """
        # By default, type is determined by class name.
        return _camel_to_snake(cls.__name__)

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
        return cattr.structure(obj, cls)

    def as_dict(self, flat=False) -> dict:
        ret = cattr.unstructure(self)
        if flat:
            ret = _flatten_dict(ret)
        return ret

    def as_formatted_dict(self, flat=False) -> dict:
        """
        Converts metadata element into a well formatted dictionary usually
        used for presenting metadata elements as tabular data.
        """
        ret = {}
        for field in self.fields():
            name = field.name
            value = getattr(self, name)
            # Convert bytes to a string representation.
            if isinstance(value, bytes):
                value = str(value)
            # Recursively handle nested elements.
            if isinstance(value, Element):
                value = value.as_formatted_dict()
            ret[name] = value

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
        return elements

    def post_processing(self, report):
        """
        Performs and adds extra additions to the Report when the Element gets created.
        :param report: mwcp Report used to add metadata.
        """

    def add_tag(self, *tags: Iterable[str]) -> "Element":
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


# Create a hook that uses the "type" field to determine the appropriate class to use for Element.
def _structure_hook(value: dict, klass):
    # Value may be partially converted
    # github.com/python-attrs/cattrs/issues/78
    if hasattr(value, "__attrs_attrs__"):
        return value

    value = dict(value)  # create copy

    # Determine class to use based on "type" field.
    klass = Element._registry[value.pop("type")]

    # Remove None values from dictionary, since that seems to be causing
    # cattr (or our autocasting) to convert them to the string "None"
    # TODO: Remove when github.com/python-attrs/cattrs/issues/53 is solved.
    value = _strip_null(value)

    # cattrs doesn't support init=False values, so we need to remove tags and
    # then re-add them.
    tags = value.pop("tags")
    ret = cattr.structure_attrs_fromdict(value, klass)
    ret.tags = tags
    return ret


cattr.register_structure_hook(Element, _structure_hook)


# Create hook to add a "type" field to help with serialization of Element types.
def _unstructure_hook(obj):
    # obj may be None because we don't use Optional in our typing.
    if obj is None:
        return obj
    return {"type": obj._type(), **cattr.unstructure_attrs_asdict(obj)}


cattr.register_unstructure_hook(Element, _unstructure_hook)


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


@attr.s(**config)
class Path(Metadata):
    """
    Filesystem path used by malware. may include both a directory and filename.

    e.g.
        Path("C:\\windows\\temp\\1\\log\\keydb.txt", is_dir=False)  # pass full path
        Path(directory_path=f"C:\foo\", name="bar.exe", is_dir=False)  # know location and name of dropped file
        Path(directory_path=f"C:\foo\", name="logs", is_dir=True)   # know location and name of a directory that gets created/used
        Path(directory_path=f"C:\foo\", is_dir=False)  # know location of dropped file but name is unknown/varies
        Path(name="bar.exe", is_dir=False)   # know name of of dropped file, but location is unknown
        Path(directory_path=f"C:\foo\", is_dir=True)  # know location of a directory that gets created/used, but name of directory is unknown.

    """
    path: str = None
    directory_path: str = None
    name: str = None
    is_dir: bool = None
    file_system: str = None  # NTFS, ext4, etc.

    def __attrs_post_init__(self):
        if self.path:
            if not self.directory_path:
                self.directory_path = ntpath.dirname(self.path)
            if not self.name:
                self.name = ntpath.basename(self.path)
        elif self.directory_path and self.name:
            self.path = ntpath.join(self.directory_path, self.name)


def Directory(path: str) -> Path:
    return Path(path, is_dir=True)


def FilePath(path: str) -> Path:
    return Path(path, is_dir=False)


def FileName(name: str) -> Path:
    return Path(name=name, is_dir=False)


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
    """
    value: str


@attr.s(**config)
class Credential(Metadata):
    """
    Collection of username and password used as credentials.

    e.g.
        Credential(username="admin", password="123456")
    """
    username: str = None
    password: str = None


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


@attr.s(**config)
class Socket(Metadata):
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
    # Determines if socket is for a C2 server.
    #   True == known C2, False == known not a C2, None == unknown
    c2: bool = None
    listen: bool = None

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


def SocketAddress(*args, **kwargs) -> Socket:
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version. "
        "Please use Socket() instead.",
        DeprecationWarning
    )
    return Socket(*args, **kwargs)


def C2SocketAddress(address: str, port: int = None, protocol: str = None) -> Socket:
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version",
        DeprecationWarning
    )
    return Socket(address=address, port=port, network_protocol=protocol, c2=True)


def Port(port: int, protocol: str = None) -> Socket:
    """
    TCP or UDP port.
    This generally refers to outbound connections where the malware is the client.
    Other network layer protocols, such as ICMP can be represented here.
    Application layer connections, such as HTTP, should be indicated by making a URL instead.
    """
    socket = Socket(port=port, network_protocol=protocol)
    socket._from_port = True
    return socket


def ListenPort(port: int, protocol: str = None) -> Socket:
    socket = Socket(port=port, network_protocol=protocol, listen=True)
    socket._from_port = True
    return socket


def Address(address: str) -> Socket:
    return Socket(address=address)


def C2Address(address: str) -> Socket:
    return Socket(address=address, c2=True)


@attr.s(**config)
class URL(Metadata):
    """
    RFC 3986 URL

    e.g.
        URL("https://10.11.10.13:443/images/baner.jpg")

        creds = Credential(username="user", password="pass")
        URL(socket=Socket("mail.badhost.com"), application_protocol="smtp", credential=creds))
    """
    url: str = None
    socket: Socket = None
    path: str = None
    query: str = None
    application_protocol: str = None
    credential: Credential = None

    _URL_RE = re.compile(
        r"((?P<app_protocol>[a-z\.\-+]{1,40})://)?(?P<address>\[?[^/]+\]?)"
        r"(?P<path>/[^?]+)?(?P<query>.*)",
        flags=re.IGNORECASE
    )

    def __attrs_post_init__(self):
        if self.url is not None:
            self._parse_url(self.url)

    def _parse_url(self, url: str):
        """
        Parses provided url in order to set individual components.
        """
        match = self._URL_RE.match(url)
        if not match:
            # TODO: To keeps backwards compatibility we still must allow the url
            #   to be set.
            logger.error(f"Error parsing as url: {url}")
            return

        app_protocol = match.group("app_protocol")
        path = match.group("path")
        query = match.group("query")
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
                raise ValidationError(f"Invalid URL {url}, found ':' at end without a port.")
            elif not port:
                port = None

        if not self.socket:
            self.socket = Socket(address=address, port=port)
        if not self.path:
            self.path = path
        if not self.query:
            self.query = query
        if not self.application_protocol:
            self.application_protocol = app_protocol

    @property
    def c2(self) -> Optional[bool]:
        return self.socket and self.socket.c2

    @c2.setter
    def c2(self, value: bool):
        """
        Convenience for setting url as a c2.
        """
        if not isinstance(value, bool):
            raise ValidationError(f"C2 {repr(value)} is not a boolean.")
        if not self.socket:
            self.socket = Socket()
        self.socket.c2 = value

    @property
    def listen(self) -> Optional[bool]:
        return self.socket and self.socket.listen

    @listen.setter
    def listen(self, value: bool):
        """
        Convenience for setting url as a listen.
        """
        if not isinstance(value, bool):
            raise ValidationError("Listen {repr(value)} is not a boolean.")
        if not self.socket:
            self.socket = Socket()
        self.socket.listen = value


def C2URL(
        url: str = None,
        socket: Socket = None,
        path: str = None,
        query: str = None,
        application_protocol: str = None,
        credential: Credential = None
) -> URL:
    url = URL(
        url=url,
        socket=socket,
        path=path,
        query=query,
        application_protocol=application_protocol,
        credential=credential
    )
    url.c2 = True
    return url


def URLPath(path: str) -> URL:
    """Path portion of URL"""
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version. "
        "Please use URL() instead.",
        DeprecationWarning
    )
    return URL(path=path)


def Proxy(
        username: str = None,
        password: str = None,
        address: str = None,
        port: int = None,
        protocol: str = None
) -> URL:
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
    url = URL()
    if address or port or protocol:
        url.socket = Socket(address=address, port=port, network_protocol=protocol)
    if username or password:
        url.credential = Credential(username=username, password=password)
    url.add_tag("proxy")
    return url


def ProxySocketAddress(address: str, port: int = None, protocol: str = None) -> URL:
    warnings.warn(
        "This function is a temporary helper. This may be removed in a future version. "
        "Please use Proxy() instead.",
        DeprecationWarning
    )
    return Proxy(address=address, port=port, protocol=protocol)


def ProxyAddress(address: str) -> URL:
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
) -> URL:
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
    if url and address:
        raise ValidationError("Must provide either url or address. Both provided.")
    if url:
        url_object = URL(url)
    else:
        url_object = URL(socket=Socket(address=address, port=port))
    if username or password:
        url_object.credential = Credential(username=username, password=password)
    url_object.application_protocol = "ftp"
    return url_object


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


@attr.s(**config)
class Event(Metadata):
    """
    Event object

    e.g.
        Event("MicrosoftExit")
    """
    value: str


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


GUID = UUID  # alias


@attr.s(**config)
class UUIDLegacy(Metadata):
    """
    Legacy version of UUID that doesn't validate or convert the uuid in order to ensure
    the original raw strings is displayed.

    WARNING: This should not be used in new code. Use UUID instead.
    """
    value: str


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


@attr.s(**config)
class Interval(Metadata):
    """
    Time malware waits between beacons or other activity given in seconds.

    e.g.
        Interval(3.0)
        Interval(0.1)
    """
    value: float


@attr.s(**config)
class IntervalLegacy(Metadata):
    """
    Legacy version of interval that uses a string type instead of float in order to preserve original
    display of the interval.
    This was done in order to ensure the decimal is either included or not depending on what the user provides.

    WARNING: This should not be used in new code!
    """
    value: str


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

    def __attrs_post_init__(self):
        # Determines if key is an encoded utf8 string.
        # (Used for backwards compatibility support.)
        self._raw_string = False

    def as_formatted_dict(self, flat=False) -> dict:
        # Convert key into hex number
        key = f"0x{self.key.hex()}"

        # Add context if encoding can be detected from key.
        encoding = None
        if self._raw_string:
            encoding = "utf-8"
        else:
            # Test for encoding by determining which encoding creates pure ascii.
            for test_encoding in ["utf-16", "ascii", "utf-8"]:
                try:
                    if self.key.decode(test_encoding).isprintable():
                        encoding = test_encoding
                        break
                except UnicodeDecodeError:
                    continue
        if encoding:
            key += f' ("{self.key.decode(encoding)}")'

        return {
            "tags": self.tags,
            "key": key,
            "algorithm": self.algorithm,
            "mode": self.mode,
            "iv": f"0x{self.iv.hex()}" if self.iv else None,
        }


def EncryptionKeyLegacy(key: str) -> EncryptionKey:
    """
    Legacy version of 'key' field which takes a string value instead of bytes.
    """
    warnings.warn(
        "EncryptionKeyLegacy is only for backwards compatibility support. Please use EncryptionKey instead.",
        DeprecationWarning
    )
    encryption_key = EncryptionKey(key.encode("utf-8"))
    encryption_key._raw_string = True
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


@attr.s(**config)
class Mutex(Metadata):
    """
    Mutex name used to prevent multiple executions of malware

    e.g.
        Mutex("ithinkimalonenow")
        Mutex("0036a8117afa")
    """
    value: str


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

    def as_formatted_dict(self, flat=False) -> dict:
        ret = super().as_formatted_dict()
        # Don't show value_format.
        del ret["value_format"]
        return ret


@attr.s(**config)
class Pipe(Metadata):
    r"""
    Named, one-way or duplex pipe for communication between the pipe server and one or more pipe clients.

    e.g.
        Pipe("\\.\\pipe\\namedpipe")
    """
    value: str


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
            logger.warning(f"Failed to base64 decode data in '{child.tag}': {e}")

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


# TODO: legacy helpers
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


@attr.s(**config)
class UserAgent(Metadata):
    """
    Software identifier used by malware

    e.g.
        UserAgent("Mozilla/4.0 (compatible; MISE 6.0; Windows NT 5.2)")
    """
    value: str


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


@attr.s(**config)
class File(Metadata):
    """
    The original input malware file that triggered parsing or extracted file.

    :var name: Name of the file.
    :var description: Description of the file.
    :var md5: MD5 hash of the file represented as a hex string.
    :var sha1: SHA1 hash of the file represented as a hex string.
    :var sha256: SHA256 hash of the file represented as a hex string.
    :var architecture: Type of architecture of the file (if applicable)
    :var compile_time: UTC Timestamp the file was compiled as reported (if applicable)
    :var file_path: Path where the file exists or has been written out to on the local file system.
    :var data: Raw bytes of the file.
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

    def __attrs_post_init__(self):
        if self.data is not None:
            if not self.md5:
                self.md5 = hashlib.md5(self.data).hexdigest()
            if not self.sha1:
                self.sha1 = hashlib.sha1(self.data).hexdigest()
            if not self.sha256:
                self.sha256 = hashlib.sha256(self.data).hexdigest()

    # TODO: Add validation for hashes.

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
        ).add_tag(*file_object.tags)


# Helper aliases
InputFile = File  # Original input malware file that triggered parsing.
ResidualFile = File  # Relevant or related file created during parsing of malware.


@attr.s(**config)
class Report(Element):
    """
    Defines the report of all metadata elements.

    :var mwcp_version: The version of MWCP used.
    :var input_file: The initial file processed.
    :var parser: The initial parser used to process the file.
    :var errors: List of error messages that have occurred.
    :var logs: List of all log messages that have occurred.
    :var metadata: List of extracted metadata elements.
    """
    mwcp_version: str = attr.ib(init=False, factory=lambda: mwcp.__version__)
    input_file: File = None
    parser: str = None
    errors: List[str] = attr.ib(factory=list)
    logs: List[str] = attr.ib(factory=list)
    metadata: List[Metadata] = attr.ib(factory=list)
