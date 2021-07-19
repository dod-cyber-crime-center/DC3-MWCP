"""
Schema for reportable metadata.

- Using attrs for easy of use and validation.
"""
import base64
import datetime
import hashlib
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
import cattr

import mwcp
from mwcp.exceptions import ValidationError

logger = logging.getLogger(__name__)


cattr = cattr.GenConverter()

# Register support for pathlib.
cattr.register_structure_hook(pathlib.Path, lambda d, t: pathlib.Path(d))
cattr.register_unstructure_hook(pathlib.Path, str)


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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Element:
    """
    Represents a collection of Elements that together represent an idea.

    These should be created using dataclass for convenience.
    """
    tags: Set[str] = attr.ib(init=False, factory=set)

    @classmethod
    def _type(cls):
        """This function is used to determine name identifier for the """
        # By default, type is determined by class name.
        return _camel_to_snake(cls.__name__)

    @classmethod
    def fields(cls):
        return attr.fields(cls)

    @classmethod
    def from_dict(cls, obj: dict) -> "Element":
        return cattr.structure(obj, cls)

    def as_dict(self, flat=False) -> dict:
        ret = cattr.unstructure(self)
        if flat:
            ret = _flatten_dict(ret)
        return ret

    def as_formatted_dict(self) -> dict:
        """
        Converts metadata element into a well formatted dictionary usually
        used for presenting metadata elements as tabular data.
        """
        return self.as_dict(flat=True)

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
                return super().default(o)
        return json.dumps(self, cls=_JSONEncoder, indent=4)

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
            self.tags.add(tag)
        return self


# Create a hook that uses the "type" field to determine the appropriate class to use for Element.
def _structure_hook(value: dict, klass):
    # Value may be partially converted
    # github.com/Tinche/cattrs/issues/78
    if hasattr(value, "__attrs_attrs__"):
        return value

    value = dict(value)  # create copy

    # Determine class to use based on "type" field.
    type = value.pop("type")
    for _klass in Element.__subclasses__():
        if _klass._type() == type:
            klass = _klass

    # Remove None values from dictionary, since that seems to be causing
    # cattr (or our autocasting) to convert them to the string "None"
    # TODO: Remove when github.com/Tinche/cattrs/issues/53 is solved.
    value = _strip_null(value)

    # cattrs doesn't support init=False values, so we need to remove tags and
    # then re-add them.
    tags = value.pop("tags")
    ret = cattr.structure_attrs_fromdict(value, klass)
    ret.tags = set(tags)
    return ret


cattr.register_structure_hook(Element, _structure_hook)


# Create hook to add a "type" field to help with serialization of Element types.
def _unstructure_hook(obj):
    # obj may be None because we don't use Optional in our typing.
    if obj is None:
        return obj
    return {"type": obj._type(), **cattr.unstructure_attrs_asdict(obj)}


cattr.register_unstructure_hook(Element, _unstructure_hook)


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Path(Element):
    """
    Filesystem path used by malware. may include both a directory and filename.

    e.g.
        Path("C:\\windows\\temp\\1\\log\\keydb.txt", is_dir=False)

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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Alphabet(Element):
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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Credential(Element):
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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Socket(Element):
    """
    A collection of address, port, and protocol used together to make a socket
    connection.

    e.g.
        Socket(address="bad.com", port=21, protocol="tcp")
    """
    address: str = None  # ip address or domain  # TODO: should this be split up?
    port: int = attr.ib(default=None)
    network_protocol: str = attr.ib(
        default=None,
        converter=lambda v: str(v).lower() if v is not None else v
    )
    # Determines if socket is for a C2 server.
    #   True == known C2, False == known not a C2, None == unknown
    c2: bool = None
    listen: bool = None

    _VALID_PROTOCOLS = {"tcp", "udp", "icmp"}

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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class URL(Element):
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
        r"(?P<app_protocol>[a-z\.\-+]{1,40})://(?P<address>\[?[^/]+\]?)"
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
            self.socket = Socket(address=address, port=port, network_protocol="tcp")
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


def C2URL(url: str) -> URL:
    url = URL(url)
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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class EmailAddress(Element):
    """
    Email address

    e.g.
        EmailAddress("email@bad.com")
    """
    value: str = attr.ib()

    @value.validator
    def _validate(self, attribute, value):
        if "@" not in value:
            raise ValidationError(f"Email address should at least have a '@' character.")


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Event(Element):
    """
    Event object

    e.g.
        Event("MicrosoftExit")
    """
    value: str


# NOTE: We are not typing this as uuid.UUID because that has caused issues with serialization.
#   Validation occurs in the below function.
@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class _UUID(Element):
    """
    A 128-bit number used to identify information, also referred to as a GUID.

    e.g.
        _UUID("654e5cff-817c-4e3d-8b01-47a6f45ae09a")
    """
    value: str

    @classmethod
    def _type(cls):
        return "uuid"


def UUID(value: Union[str, bytes, int, uuid.UUID]) -> _UUID:
    """
    Constructor for UUID metadata element.
    If user provides a uuid.UUID object it is converted into a string.
    This is necessary because uuid.UUID can't handle being constructed twice.
    :param value:
    :return:
    """
    # TODO: Move this validation/converter into the metadata element
    #   when we no longer need to support UUIDLegacy.
    try:
        if isinstance(value, str):
            value = uuid.UUID(value)
        elif isinstance(value, bytes):
            value = uuid.UUID(bytes=value)
        elif isinstance(value, int):
            value = uuid.UUID(int=value)
    except Exception as e:
        raise ValidationError(f"Invalid UUID: {e}")

    return _UUID(str(value))


def UUIDLegacy(value: str) -> _UUID:
    """
    Legacy version of UUID that doesn't validate or convert the uuid in order to ensure
    the original raw strings is displayed.
    """
    warnings.warn(
        "UUIDLegacy is only for backwards compatibility support. Please use UUID instead.",
        DeprecationWarning
    )
    return _UUID(value)


GUID = UUID  # alias


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class InjectionProcess(Element):
    """
    Process into which malware is injected.
    Usually this is a process name but it make take other forms such as a filename of the executable.

    e.g.
        InjectionProcess("iexplore")
        InjectionProcess("svchost")
    """
    value: str


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Interval(Element):
    """
    Time malware waits between beacons or other activity given in seconds.

    e.g.
        Interval(3.0)
        Interval(0.1)
    """
    value: float


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class _IntervalLegacy(Element):
    """
    Legacy version of interval that uses a string type instead of float in order to preserve original
    display of the interval.
    This was done in order to ensure the decimal is either included or not depending on what the user provides.
    """
    value: str

    @classmethod
    def _type(cls):
        return "interval"


def IntervalLegacy(value: str) -> _IntervalLegacy:
    warnings.warn(
        "IntervalLegacy is only for backwards compatibility support. Please use Interval instead.",
        DeprecationWarning
    )
    return _IntervalLegacy(value)


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class EncryptionKey(Element):
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

    def as_formatted_dict(self) -> dict:
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
                    self.key.decode(test_encoding).encode("ascii")
                    encoding = test_encoding
                    break
                except (UnicodeDecodeError, UnicodeEncodeError):
                    continue
        if encoding:
            key += f' ("{self.key.decode(encoding)}")'

        return {
            "tags": self.tags,
            "key": key,
            "algorithm": self.algorithm,
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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class DecodedString(Element):
    """
    Extracted decrypted or decoded string.

    e.g.
        DecodedString("badman")
        DecodedString("evilstring", encryption_key=EncryptionKey(b"secret", algorithm="xor"))
    """
    value: str
    encryption_key: EncryptionKey = None


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class MissionID(Element):
    """
    Attacker specified identifier encoded in malware,
    usually reflected in beacons and often related to target or time of attack.

    e.g.
        MissionID("target4")
        MissionID("201412")
    """
    value: str


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Mutex(Element):
    """
    Mutex name used to prevent multiple executions of malware

    e.g.
        Mutex("ithinkimalonenow")
        Mutex("0036a8117afa")
    """
    value: str


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Other(Element):
    """
    All items other that don't fit within the existing declared schema.
    Items may also be duplicated here to provide malware specific content.

    e.g.
        Other(key="keylogger", value="True")
    """
    key: str
    value: Union[str, bytes]


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Pipe(Element):
    r"""
    Named, one-way or duplex pipe for communication between the pipe server and one or more pipe clients.

    e.g.
        Pipe("\\.\\pipe\\namedpipe")
    """
    value: str


class RegistryDataType(IntEnum):
    """Registry value data types in winreg.h"""
    REG_NONE = 0
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_DWORD_BIG_ENDIAN = 5
    REG_LINK = 6
    REG_MULTI_SZ = 7
    REG_QWORD = 11


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Registry(Element):
    """
    Registry key and value.

    e.g.
        Registry(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            data="c:\\update.exe",
        )
    """
    path: str = None
    key: str = None
    value: str = None  # registry key, value name, combination of the two
    data: Any = None
    # data_type: RegistryDataType = None  # TODO

    def __attrs_post_init__(self):
        if self.path is not None:
            # TODO: support other file system path types.
            key, _, value = self.path.rpartition("\\")
            if self.key is None:
                self.key = key
            if self.value is None:
                self.value = value
        elif self.key and self.value:
            self.path = "\\".join([self.key, self.value])


def RegistryData(data: str) -> Registry:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Registry() instead.", DeprecationWarning
    )
    return Registry(data=data)


def RegistryPath(path: str) -> Registry:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Registry() instead.", DeprecationWarning
    )
    return Registry(path)


def RegistryPathData(path: str, data: str) -> Registry:
    warnings.warn(
        "This is a temporary helper that may be removed in a future version. "
        "Please use Registry() instead.", DeprecationWarning
    )
    return Registry(path, data=data)


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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class RSAPrivateKey(Element):
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

    def as_formatted_dict(self) -> dict:
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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class RSAPublicKey(Element):
    """
    RSA public key containing: public_exponent, modulus
    """
    public_exponent: int = None
    modulus: int = None

    def as_formatted_dict(self) -> dict:
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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Service(Element):
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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class SSLCertSHA1(Element):
    """
    SSL Certificate SHA-1 Hash

    e.g.
        SSLCertSHA1("c29d79df9b5416fd416c31e57cd525dfc23a8f66")
    """
    value: str = attr.ib()

    _SHA1_RE = re.compile("[0-9a-fA-F]{40}")

    @value.validator
    def _validate(self, attribute, value):
        if not self._SHA1_RE.match(value):
            raise ValidationError(f"Invalid SHA1 hash found: {value!r}")


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class UserAgent(Element):
    """
    Software identifier used by malware

    e.g.
        UserAgent("Mozilla/4.0 (compatible; MISE 6.0; Windows NT 5.2)")
    """
    value: str


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class Version(Element):
    """
    The version of the malware.
    To the degree possible this should be based directly on artifacts from the malware.

    e.g.
        Version("3.1")
        Version("incrementing XOR encoding")
    """
    value: str


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class _File(Element):
    """
    Generic interface for describing a file.
    NOTE: This should not be used directly. Please use either InputFile or ResidualFile.

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
    compile_time: str = None  # TODO: make this a datetime type?
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


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class InputFile(_File):
    """
    Original input malware file that triggered parsing.
    """


# TODO: InputFile and ResidualFile should be the same element type.
@attr.s(auto_attribs=True, field_transformer=_auto_convert)
class ResidualFile(_File):
    """
    Relevant or related file created during parsing of malware.
    """


@attr.s(auto_attribs=True, field_transformer=_auto_convert)
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
    input_file: InputFile = None
    parser: str = None
    errors: List[str] = attr.ib(factory=list)
    logs: List[str] = attr.ib(factory=list)
    metadata: List[Element] = attr.ib(factory=list)
