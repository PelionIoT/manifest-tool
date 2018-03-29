# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2016-2017 ARM Limited or its affiliates
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------
import codecs, uuid, binascii
from pyasn1.codec.native.decoder import decode as native_decode
from pyasn1.codec.native.encoder import encode as native_encode

def get_component_type(schema):
    """Due to quirks in the pyasn1 library, for some schema types the componentType is not
    properly set, so we use this convinience method to access the underlying data if required"""
    return schema.componentType if (len(schema.componentType) > 0) else schema._componentType

def obj2asn(value, schema):
    """
    Converts python object into the pyasn1 object following the schema provided. The (potentially nested)
    object (commenly converted from JSON) will of course have to match the format of the ASN.1 defintion.

    Given the following schema:

        MyStruct SEQUENCE ::= {
            id INTEGER,
            name UTF8String
        }

    Example:

        >>> import schema_definition
        >>> from pyasn1.codec.der import encoder
        >>> value = JSON.loads('{ "id": 1, "name": "David" }')
        >>>
        >>> # pyasn1 schema can be generated from ASN.1 definition using asn2py script, here
        >>> # exported as schema_definition.py, which we can import as a python module.
        >>> asn_obj = obj2asn(value, schema_definition.MyStruct())
        >>>
        >>> # We can now encode this data to whatever format we want
        >>> der_bytes = encoder.encode(asn_obj)
    """
    return native_decode(value, schema)

def asn2obj(asn, numericEnum=False):
    """
    Decodes ASN objects into Python object structures (array or dictionary). See
    opposing function `obj2asn` for the encoding logic.

    This is commonly called for when you have a pyasn1 object (e.g. as a result
    of running as pyasn1 decode from raw bytes) and you want to output into JSON
    or similar.

    Example, given the same schema as defined in `obj2asn`:

        >>> from pyasn1.codec.der import decoder
        >>> import schema_definition
        >>> import json
        >>> raw_bytes = b"..."
        >>> asn_obj = decoder.decode(raw_bytes, schema_definition.MyStruct())
        >>> print json.dumps(asn2obj(asn_obj), indent=4)
        {
            "id": 1,
            "name": "David"
        }
    """

    if asn.__class__.__name__ == 'Any':
        return asn.asOctets()

    # If type_id is not set, we have a primitive type
    if not asn.typeId:
        # If the type has base type which is UTF8String, we use the string
        # representation of these bytes - and not the raw representation as
        # value. Might be a better way of checking if it's a string class, but
        # this works fine.
        if 'UTF8String' in [b.__name__ for b in asn.__class__.__bases__] or \
            asn.__class__.__name__ == 'UTF8String':
            if isinstance(asn._value, bytes):
                return asn._value.decode(asn._encoding)
            return str(asn._value)

        # Translate the UUID type into URN format (RFC-4122)
        if asn.__class__.__name__ == 'UUID':
            if len(asn._value) != 16:
                return binascii.b2a_hex(asn.asOctets())
            else:
                return str(uuid.UUID(bytes=asn._value))

        # The type OBJECT IDENTIFIER becomes a tuple type, so we
        # decode it into a "." delimited string
        if isinstance(asn._value, tuple):
            return '.'.join(map(str, asn._value))

        # The ASN type Boolean becomes 1/0, but we would like to translate
        # to Python booleans.
        if asn.__class__.__name__ == 'Boolean':
            return bool(asn._value)

        if asn.__class__.__name__ == 'Enumerated':
            if numericEnum:
                return int(asn._value)
            else:
                return asn.getNamedValues().getName(asn)
        # If we have bytes, we encode into hex representation. Hacky, but we
        # need something JSON serializable.
        if isinstance(asn._value, bytes):
            return codecs.encode(asn._value, 'hex').decode(asn._encoding)

        return asn._value

    # If type_id is 1 or 2 we have a Sequence/SetOf type (i.e. an array)
    elif asn.typeId <= 2:
        return [asn2obj(e, numericEnum) for e in asn._componentValues]

    # If not primitive nor array, we have a Sequence-like type and we handle
    # this as a dictionary. We iterate through each key where the value is
    # set (i.e. ignoring empty optional fields) and recursivly get the decoded
    # value block.
    j = {}
    if hasattr(asn, '_componentValues'):
        for idx, v in enumerate(asn._componentValues):
            if v is None or (hasattr(v,'__len__') and len(v) is 0): continue
            j[asn.getNameByPosition(idx)] = asn2obj(v,numericEnum)
    return j

def asn2obj_native(asn):
    """
    Decodes ASN objects into Python object structures (array or dictionary). See
    opposing function `obj2asn` for the encoding logic.

    This is commonly called for when you have a pyasn1 object (e.g. as a result
    of running as pyasn1 decode from raw bytes) and you want to output into JSON
    or similar.

    Example, given the same schema as defined in `obj2asn`:

        >>> from pyasn1.codec.der import decoder
        >>> import schema_definition
        >>> import json
        >>> raw_bytes = b"..."
        >>> asn_obj = decoder.decode(raw_bytes, schema_definition.MyStruct())
        >>> print json.dumps(asn2obj(asn_obj), indent=4)
        {
            "id": 1,
            "name": "David"
        }
    """
    return native_encode(asn)

def bin2obj(value, schema, decoder, numericEnum = False):
    decoded_asn = decoder.decode(value, schema)[0]
    return asn2obj(decoded_asn, numericEnum)

def bin2obj_native(value, schema, decoder):
    decoded_asn = decoder.decode(value, schema)[0]
    return asn2obj_native(decoded_asn)
