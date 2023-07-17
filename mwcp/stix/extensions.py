"""
Provides support for STIX 2.1 extensions that have not yet been added to the STIX Python library as top level objects.
"""

from collections import OrderedDict

from stix2 import registry
from stix2.v21.base import _STIXBase21
from stix2.v21 import _Observable
from stix2.properties import (
    EmbeddedObjectProperty,
    HexProperty,
    IDProperty,
    ListProperty,
    OpenVocabProperty,
    ReferenceProperty,
    StringProperty,
    TimestampProperty,
    TypeProperty,
    ExtensionsProperty,
)
from stix2.v21.common import GranularMarking

from isodate import parse_duration
from isodate.isoerror import ISO8601Error

OBSERVED_STRING_PURPOSE_OV = [
    "campaign-id",
    "document-text",
    "pipe",
    "user-agent",
    "uuid",
    "unknown",
]


class ObservedString(_Observable):
    """
    This STIX SCO is an extension and used to track unique strings observed in content so it can be easily deduplicated,
    shared and searched for
    """

    _type = "observed-string"
    _properties = OrderedDict(
        [
            ("type", TypeProperty(_type, spec_version="2.1")),
            ("spec_version", StringProperty(fixed="2.1")),
            ("id", IDProperty(_type, spec_version="2.1")),
            ("value", StringProperty(required=True)),
            ("purpose", OpenVocabProperty(OBSERVED_STRING_PURPOSE_OV, required=True)),
            (
                "object_marking_refs",
                ListProperty(
                    ReferenceProperty(
                        valid_types="marking-definition", spec_version="2.1"
                    )
                ),
            ),
            ("granular_markings", ListProperty(GranularMarking)),
            ("extensions", ExtensionsProperty(spec_version="2.1")),
        ]
    )

    _id_contributing_properties = ["value", "purpose"]

    def __init__(self, *args, **kwargs) -> None:
        # always make sure the property extension details are populated
        extensions = kwargs.get("extensions", {})
        extensions["extension-definition--8b1aa84c-5532-4c69-a8e7-b6170facfd3d"] = {
            "extension_type": "new-sco"
        }

        kwargs["extensions"] = extensions
        super().__init__(*args, **kwargs)


class CryptoCurrencyAddress(_Observable):
    """
    This STIX SCO is an extension and used to track cryptocurrecy addresses
    """

    _type = "crypto-currency-address"
    _properties = OrderedDict(
        [
            ("type", TypeProperty(_type, spec_version="2.1")),
            ("spec_version", StringProperty(fixed="2.1")),
            ("id", IDProperty(_type, spec_version="2.1")),
            ("address", StringProperty(required=True)),
            ("currency_type", StringProperty()),
            (
                "object_marking_refs",
                ListProperty(
                    ReferenceProperty(
                        valid_types="marking-definition", spec_version="2.1"
                    )
                ),
            ),
            ("granular_markings", ListProperty(GranularMarking)),
            ("extensions", ExtensionsProperty(spec_version="2.1")),
        ]
    )

    def __init__(self, *args, **kwargs) -> None:
        # always make sure the property extension details are populated
        extensions = kwargs.get("extensions", {})
        extensions["extension-definition--4b12a3b5-0d80-464b-914d-dcbfbd980e64"] = {
            "extension_type": "new-sco"
        }

        kwargs["extensions"] = extensions
        super().__init__(*args, **kwargs)

    _id_contributing_properties = ["address", "currency_type"]


class SymmetricEncryption(_Observable):
    """
    This STIX SCO is used to supply information about encryption keys found in Files or other sources
    """

    _type = "symmetric-encryption"
    _properties = OrderedDict(
        [
            ("type", TypeProperty(_type, spec_version="2.1")),
            ("spec_version", StringProperty(fixed="2.1")),
            ("id", IDProperty(_type, spec_version="2.1")),
            ("key_hex", HexProperty()),
            ("iv_hex", HexProperty()),
            ("algorithm", StringProperty()),
            ("mode", StringProperty()),
            (
                "object_marking_refs",
                ListProperty(
                    ReferenceProperty(
                        valid_types="marking-definition", spec_version="2.1"
                    )
                ),
            ),
            ("granular_markings", ListProperty(GranularMarking)),
            ("extensions", ExtensionsProperty(spec_version="2.1")),
        ]
    )

    _id_contributing_properties = ["key_hex", "iv_hex", "mode", "algorithm"]

    def __init__(self, *args, **kwargs) -> None:
        # always make sure the property extension details are populated
        extensions = kwargs.get("extensions", {})
        extensions["extension-definition--fb989191-187f-4c11-81cd-4a699a00835d"] = {
            "extension_type": "new-sco"
        }

        kwargs["extensions"] = extensions
        super().__init__(*args, **kwargs)

    def _check_object_constraints(self) -> None:
        super()._check_object_constraints()
        self._check_at_least_one_property(["key_hex", "iv_hex", "mode", "algorithm"])


class TriggerComponent(_STIXBase21):
    _properties = OrderedDict(
        [
            ("type", StringProperty(required=True)),
            ("trigger_type", StringProperty(required=True)),
            ("start", TimestampProperty(required=False)),
            ("interval", StringProperty(required=True)),
        ]
    )

    def _check_object_constraints(self) -> None:
        super()._check_object_constraints()

        # this is required to be a valid ISO 8601 time delta string if present
        if self.interval is not None:
            try:
                parse_duration(self.interval)
            except ISO8601Error as iso:
                raise ValueError(
                    f'interval \'{self._properties["interval"]}\' is not a valid ISO 8601 time delta'
                ) from iso


class ScheduledTask(_Observable):
    """
    This STIX SCO stores information for scheduled tasks
    """

    _type = "scheduled-task"
    _properties = OrderedDict(
        [
            ("type", TypeProperty(_type, spec_version="2.1")),
            ("spec_version", StringProperty(fixed="2.1")),
            ("id", IDProperty(_type, spec_version="2.1")),
            ("name", StringProperty(required=True)),
            ("description", StringProperty()),
            ("author", StringProperty()),
            ("triggers", ListProperty(EmbeddedObjectProperty(type=TriggerComponent))),
            (
                "user_account_ref",
                ReferenceProperty(spec_version="2.1", valid_types="user-account"),
            ),
            (
                "object_marking_refs",
                ListProperty(
                    ReferenceProperty(
                        valid_types="marking-definition", spec_version="2.1"
                    )
                ),
            ),
            ("granular_markings", ListProperty(GranularMarking)),
            ("extensions", ExtensionsProperty(spec_version="2.1")),
        ]
    )

    _id_contributing_properties = [
        "name",
        "description",
        "author",
        "triggers",
        "user_account_ref",
        "extensions",
    ]

    def __init__(self, *args, **kwargs) -> None:
        # always make sure the property extension details are populated
        extensions = kwargs.get("extensions", {})
        extensions["extension-definition--936177d9-884c-48a9-9883-c768b4ea0fb0"] = {
            "extension_type": "new-sco"
        }

        kwargs["extensions"] = extensions
        super().__init__(*args, **kwargs)


# pylint: disable=invalid-name
def rsa_private_key_extension(
    private_exponent: str,
    p: int,
    q: int,
    d_mod_p1: int,
    d_mod_q1: int,
    q_inv_mod_p: int,
) -> dict:
    """
    This takes the parameters for the x509 certificate rsa private key extension returns an extension dictionary that
    includes these
    This is not an object as it produces a property extension instead of a SCO
    """
    properties = {}

    if private_exponent:
        properties["private_exponent"] = private_exponent
    if p:
        properties["p"] = str(p)
    if q:
        properties["q"] = str(q)
    if d_mod_p1:
        properties["d_mod_p1"] = str(d_mod_p1)
    if d_mod_q1:
        properties["d_mod_q1"] = str(d_mod_q1)
    if q_inv_mod_p:
        properties["q_inv_mod_p"] = str(q_inv_mod_p)

    if len(properties) > 0:
        properties["extension_type"] = "property-extension"
        return {
            "extension-definition--b84c95f5-d48d-4e4a-b723-7d209a02deb9": properties
        }

    return {}


# The stix2 library documentation recommends the usage of CustomExtension instead of registering directly
# We are doing this since we want to make these standard paths extensions however.
# Using this access paradigm lets us copy the class definitions directly using the stix2 library for sharing
# instead of creating an internal version that uses CustomExtension and a shared version that does not.
# pylint: disable=protected-access
registry.STIX2_OBJ_MAPS["2.1"]["observables"][ObservedString._type] = ObservedString
registry.STIX2_OBJ_MAPS["2.1"]["observables"][CryptoCurrencyAddress._type] = CryptoCurrencyAddress
registry.STIX2_OBJ_MAPS["2.1"]["observables"][SymmetricEncryption._type] = SymmetricEncryption
registry.STIX2_OBJ_MAPS["2.1"]["observables"][ScheduledTask._type] = ScheduledTask
