"""
Provides support for STIX 2.1 extensions that have not yet been added to the STIX Python library as top level objects.
"""

from collections import OrderedDict

from stix2.v21 import _Observable
from stix2.properties import (
    DictionaryProperty, HexProperty, IDProperty, ListProperty, OpenVocabProperty,
    ReferenceProperty, StringProperty, TypeProperty
)
from stix2.v21.common import GranularMarking

OBSERVED_STRING_PURPOSE_OV = [
    "campaign-id",
    "pipe",
    "user-agent",
    "uuid",
]


class ObservedString(_Observable):
    """
    This STIX SCO is an extension and used to track unique strings observed in content so it can be easily deduplicated, shared and searched for
    """

    __EXTENSION_DETAILS = {"extension-definition--8b1aa84c-5532-4c69-a8e7-b6170facfd3d": {"extension_type": "new-sco"}}

    _type = "observed-string"
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version="2.1")),
        ('spec_version', StringProperty(fixed="2.1")),
        ('id', IDProperty(_type, spec_version="2.1")),
        ('value', StringProperty(required=True)),
        ('purpose', OpenVocabProperty(OBSERVED_STRING_PURPOSE_OV, required=True)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types="marking-definition", spec_version="2.1"))),
        ('granular_markings', ListProperty(GranularMarking)),
        # This uses a Dictionary instead of an Extension property because ExtensionProperty does not support fixed values
        ('extensions', DictionaryProperty(fixed=__EXTENSION_DETAILS)), 
    ])

    _id_contributing_properties = ["value", "purpose"]


class CryptoCurrencyAddress(_Observable):
    """
    This STIX SCO is an extension and used to track cryptocurrecy addresses
    """

    __EXTENSION_DETAILS = {"extension-definition--4b12a3b5-0d80-464b-914d-dcbfbd980e64": {"extension_type": "new-sco"}}

    _type = "crypto-currency-address"
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version="2.1")),
        ('spec_version', StringProperty(fixed="2.1")),
        ('id', IDProperty(_type, spec_version="2.1")),
        ('address', StringProperty(required=True)),
        ('currency_type', StringProperty()),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types="marking-definition", spec_version="2.1"))),
        ('granular_markings', ListProperty(GranularMarking)),
        # This uses a Dictionary instead of an Extension property because ExtensionProperty does not support fixed values
        ('extensions', DictionaryProperty(fixed=__EXTENSION_DETAILS)), 
    ])

    _id_contributing_properties = ["address", "currency_type"]


class SymmetricEncryption(_Observable):
    """
    This STIX SCO is used to supply information about encryption keys found in Files or other sources
    """

    __EXTENSION_DETAILS = {"extension-definition--fb989191-187f-4c11-81cd-4a699a00835d": {"extension_type": "new-sco"}}

    _type = "symmetric-encryption"
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version="2.1")),
        ('spec_version', StringProperty(fixed="2.1")),
        ('id', IDProperty(_type, spec_version="2.1")),
        ('key_hex', HexProperty()),
        ('iv_hex', HexProperty()),
        ('algorithm', StringProperty()),
        ('mode', StringProperty()),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types="marking-definition", spec_version="2.1"))),
        ('granular_markings', ListProperty(GranularMarking)),
        # This uses a Dictionary instead of an Extension property because ExtensionProperty does not support fixed values
        ('extensions', DictionaryProperty(fixed=__EXTENSION_DETAILS)), 
    ])

    _id_contributing_properties = ["key_hex", "iv_hex", "mode", "algorithm"]

    def _check_object_constraints(self):
        super()._check_object_constraints()
        self._check_at_least_one_property(["key_hex", "iv_hex", "mode", "algorithm"])


def rsa_private_key_extension(private_exponent, p, q, d_mod_p1, d_mod_q1, q_inv_mod_p) -> dict:
    """
    This takes the parameters for the x509 certificate rsa private key extension returns an extension dictionary that includes these
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
        return {"extension-definition--b84c95f5-d48d-4e4a-b723-7d209a02deb9": properties}

    return {}
