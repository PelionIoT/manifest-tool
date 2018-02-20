#!/usr/bin/env python
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
#   The confidential and proprietary information contained in this file may
#   only be used by a person authorised under and to the extent permitted
#   by a subsisting licensing agreement from ARM Limited or its affiliates.
#
#          (C) COPYRIGHT 2017 ARM Limited or its affiliates.
#              ALL RIGHTS RESERVED
#
#   This entire notice must be reproduced on all copies of this file
#   and copies of this file may only be made by a person if such person is
#   permitted to do so under the terms of a subsisting license agreement
#   from ARM Limited or its affiliates.
#----------------------------------------------------------------------------
from manifesttool.v1 import manifest_definition
from manifesttool.v1 import cms_signed_data_definition
from pyasn1.type import univ
import sys
import os.path

FileHeaderBlock = '''//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2017 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------
//
/////////////////////////////////////////////////////////////
// WARNING: THIS IS A MACHINE GENERATED FILE. DO NOT EDIT. //
/////////////////////////////////////////////////////////////
'''

MacroPrefix = 'ARM_UC_MM_DER_'
VarPrefix = 'arm_uc_mm_'

EntryPoints = [
    ('ContentInfo', cms_signed_data_definition.ContentInfo()),
    ('Manifest', manifest_definition.Manifest())
]

Accessors = []

AccessorPrefix = 'ARM_UC_mmDERGet'

accessorEntryPoint = None

def makeAccessor(entry, name, macro, obj):

    accessorDeclarationTemplate = 'arm_uc_error_t {AccessorPrefix}{name}(arm_uc_buffer_t* buffer, arm_uc_buffer_t* val);'
    accessorDefinitionTemplate = accessorDeclarationTemplate[:-1] + '''
{{
    return {AccessorPrefix}SingleValue({entry}, buffer, {macro}, val);
}}'''
    integerAccessorDeclarationTemplate = 'arm_uc_error_t {AccessorPrefix}{name}(arm_uc_buffer_t* buffer, uint64_t* val);'
    integerAccessorDefinitionTemplate = integerAccessorDeclarationTemplate[:-1] + '''
{{
    arm_uc_buffer_t field = {{0}};
    arm_uc_error_t err = {AccessorPrefix}SingleValue({entry}, buffer, {macro}, &field);
    if (err.error == ERR_NONE) {{
        *val = ARM_UC_mmDerBuf2Uint64(&field);
    }}
    return err;
}}'''

    integerType = isinstance(obj, univ.Integer) or isinstance(obj, univ.Enumerated)
    declarationTemplate = integerAccessorDeclarationTemplate if integerType else accessorDeclarationTemplate
    definitionTemplate = integerAccessorDefinitionTemplate if integerType else accessorDefinitionTemplate

    return {
        'declaration' : declarationTemplate.format(
            AccessorPrefix = AccessorPrefix,
            VarPrefix = VarPrefix,
            macro = macro,
            name = name,
            entry = entry
        ),
        'definition' : definitionTemplate.format(
            AccessorPrefix = AccessorPrefix,
            VarPrefix = VarPrefix,
            macro = macro,
            name = name,
            entry = entry
        )
    }

def tagVal(t):
    return t[0] | t[1] | t[2]

externs = []

def getDERchildren(prefix, entry, name, asn1Object):
    newPrefix = prefix + name
    varName = VarPrefix + newPrefix
    s = ['const struct arm_uc_mmDerElement {name}Elements[] = {{'.format(name = varName)]
    externs.append('extern const struct arm_uc_mmDerElement {name}Elements[];'.format(name = varName))
    subchildren = []
    declarations = []
    for i in range(len(asn1Object.getComponentType())):
        nt = asn1Object.getComponentType()[i]
        subName = nt.getName()
        macro = (MacroPrefix + newPrefix + '_' + subName).upper()
        definition, sc1 = getDERelementInit(prefix = newPrefix + '_',
                                            entry = entry,
                                            name = subName,
                                            macro = macro,
                                            asn1Object = nt.getType(),
                                            ignoreSubNodes = False,
                                            optional = nt.isOptional)
        subchildren = sc1 + subchildren
        s += ['    '+definition + ',']
        if isinstance(nt.getType(), univ.Sequence) or isinstance(nt.getType(), univ.Set):
            declarations.append('const struct arm_uc_mmDerElement* {childname} = &{parentName}[{index}];'.format (
                childname = VarPrefix + newPrefix + '_' + subName,
                parentName = VarPrefix + newPrefix + 'Elements',
                index = i
            ))
            externs.append('extern const struct arm_uc_mmDerElement* {childname};'.format(childname = VarPrefix + newPrefix + '_' + subName))
        Accessors.append(makeAccessor(entry, newPrefix + '_' + subName, macro, nt.getType()))

    s += ['};']
    s = subchildren +  s + declarations
    return s

IDs = []

def getSeqO(prefix, entry, name, asn1Object):
    varName = VarPrefix + prefix + name
    s = ['const struct arm_uc_mmDerElement {name}Elements[] = {{'.format(name = varName)]
    externs.append('extern const struct arm_uc_mmDerElement {name}Elements[];'.format(name = varName))
    externs.append('extern const struct arm_uc_mmDerElement* {name};'.format(name = varName))
    componentType = asn1Object.getComponentType()
    childName = componentType.__class__.__name__
    macro = MacroPrefix+childName.upper()
    hasChildren = False
    if macro in IDs:
        hasChildren = True

    definition, subchildren = getDERelementInit(prefix = '',
                                                entry = varName,
                                                name = childName,
                                                macro = MacroPrefix+childName.upper(),
                                                asn1Object = componentType,
                                                ignoreSubNodes = macro in IDs
                                                )
    if hasChildren:
        subchildren = []
    s += ['    '+definition]
    s += ['};']
    s += ['const struct arm_uc_mmDerElement *{name} = &{name}Elements[0];'.format(name = VarPrefix + prefix + name)]
    return subchildren + s

def getDERelementInit(prefix, entry, name, macro, asn1Object, ignoreSubNodes, optional=False):
    ElementTemplate = 'ARM_UC_MM_DER_ELEMENT_INIT({macro}, {tag:#x}, {itag:#x}, {mandatory}, {children})'
    ElementLeafTemplate = 'ARM_UC_MM_DER_ELEMENT_INIT_LEAF({macro}, {tag:#x}, {itag:#x}, {mandatory})'

    tagval = None
    # print name
    if isinstance(asn1Object, univ.Any):
        tagval = 0xFE
    elif isinstance(asn1Object, univ.Choice):
        tagval = 0xFF
    else:
        tagval = tagVal(asn1Object.tagSet[0])
    itagval = tagval
    children = []
    if len(asn1Object.tagSet) > 1:
        itagval = tagVal(asn1Object.tagSet[1])
    template = ElementLeafTemplate
    # if not hasattr(asn1Object, 'componentType'):
    #     if isinstance(asn1Object, univ.ObjectIdentifier):
    #         print univ.ObjectIdentifier()
    if not ignoreSubNodes:
        IDs.append(macro)
        if isinstance(asn1Object, univ.Set) or isinstance(asn1Object, univ.Sequence) or isinstance(asn1Object, univ.Choice):
            template = ElementTemplate
            children = getDERchildren(prefix, entry, name, asn1Object)
        elif isinstance(asn1Object, univ.SequenceOf) or isinstance(asn1Object, univ.SetOf):
            template = ElementTemplate
            children = getSeqO(prefix, entry, name, asn1Object)
    element = template.format(
        macro = macro,
        tag = tagval,
        itag = itagval,
        mandatory = {False : 'DER_MANDATORY', True: 'DER_OPTIONAL'}.get(optional),
        children = VarPrefix + prefix + name + 'Elements'
    )
    return (element, children)
    # f.write()
# def printDERblock(class):
#     for
# static const struct arm_uc_mmDerElement ResourceChoiceElements[] =
# {
#
#     ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_FW_IMAGE, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
# };

    # ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, ManifestElements)

definitions = []

for name, obj in EntryPoints:
    definition, children = getDERelementInit(entry = VarPrefix + name,
                                             name = name,
                                             macro = MacroPrefix + name.upper(),
                                             asn1Object = obj,
                                             ignoreSubNodes = False,
                                             prefix = '')
    externs.append('extern const struct arm_uc_mmDerElement* {name};'.format(name = VarPrefix + name))
    decls = [
        'const struct arm_uc_mmDerElement {name}Node = {d};'.format(name=VarPrefix + name, d=definition),
        'const struct arm_uc_mmDerElement *{name} = &{name}Node;'.format(name = VarPrefix + name)
    ]
    definitions.append('\n'.join(children + decls))
    # typeTagVal = tagVal(entrypoint.tagSet[0])
    # print('{:x}'.format(typeTagVal))

# IDs.reverse()
definitions.reverse()

outputDir = '.'

if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
    outputDir = sys.argv[1]

with open(os.path.join(outputDir, 'arm_uc_mmDERManifestParser_autogen.h'), 'w') as f:
    f.write(FileHeaderBlock+'\n')
    f.write('''#ifndef ARM_UC_MM_DER_MANIFEST_PARSER_V1_H
#define ARM_UC_MM_DER_MANIFEST_PARSER_V1_H
#include "update-client-common/arm_uc_types.h"
#include "update-client-manifest-types.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define DER_MANDATORY 0
#define DER_OPTIONAL 1

struct arm_uc_mmDerElement
{
    uint32_t id;
    const struct arm_uc_mmDerElement* subElements;
    uint8_t tag;
    uint8_t itag;
    uint8_t optional;
    uint8_t nSubElements;
};

#define ARM_UC_MM_DER_ELEMENT_INIT(ID, TAG, ITAG, OPT, CHILDREN)\
    {.id = (ID), .subElements = (CHILDREN), .tag = (TAG), .itag = (ITAG), .optional = (OPT), .nSubElements = sizeof(CHILDREN)/sizeof(struct arm_uc_mmDerElement)}
#define ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ID, TAG, ITAG, OPT)\
    {.id = (ID), .subElements = NULL, .tag = (TAG), .itag = (ITAG), .optional = (OPT), .nSubElements = 0}
''')
    f.write('#define ARM_UC_MM_DER_ID_LIST \\\n')
    f.write('\\\n'.join(['    ENUM_AUTO({})'.format(x) for x in IDs]) + '\n\n')
    f.write('''enum derIDs {
#define ENUM_AUTO(X) X,
    ARM_UC_MM_DER_ID_LIST
#undef ENUM_AUTO
};
''')
    f.write('\n'.join(externs) + '\n')
    f.write('''#ifdef __cplusplus
}
#endif


#endif // ARM_UC_MM_DER_MANIFEST_PARSER_V1_H
''')

with open(os.path.join(outputDir, 'arm_uc_mmDERManifestParser_autogen.c'), 'w') as f:
    f.write(FileHeaderBlock+'\n')
    f.write('''#include "arm_uc_mmDERManifestParser_autogen.h"
#include "arm_uc_mmDERManifestParser.h"
#include "update-client-manifest-types.h"
#include <stdio.h>

arm_uc_error_t ARM_UC_wrapMbedTLSError(int32_t mt_err) {
    return (arm_uc_error_t){.error = -mt_err, .module = MBED_TLS_ERROR_PREFIX};
}

arm_uc_error_t ARM_UC_mmDERGetSingleValue(
        const struct arm_uc_mmDerElement* desc,
        arm_uc_buffer_t* buffer,
        const uint32_t valueID,
        arm_uc_buffer_t* val)
{
    int32_t rc = ARM_UC_mmDERParseTree(desc, buffer, 1U, &valueID, val);
    arm_uc_error_t err = {ARM_UC_DP_ERR_UNKNOWN};
    if (rc < 0) {
        err = ARM_UC_wrapMbedTLSError(rc);
    } else if (rc == 0) {
        err.code = ARM_UC_DP_ERR_NONE;
    } else { //if (rc > 0)
        err.code = ARM_UC_DP_ERR_NOT_FOUND;
    }
    return err;
}
''')
    f.write('\n'.join(definitions) + '\n')

with open(os.path.join(outputDir, 'arm_uc_mmDERManifestAccessors_autogen.h'), 'w') as f:
    f.write(FileHeaderBlock+'\n')
    f.write('''#ifndef ARM_UC_MM_DER_MANIFEST_ACCESSORS_H
#define ARM_UC_MM_DER_MANIFEST_ACCESSORS_H
#include "update-client-common/arm_uc_types.h"
#include "update-client-manifest-types.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

arm_uc_error_t ARM_UC_mmDERGetSingleValue(
        const struct arm_uc_mmDerElement* desc,
        arm_uc_buffer_t* buffer,
        const uint32_t valueID,
        arm_uc_buffer_t* val);
''')

    f.write('\n'.join([x['declaration'] for x in Accessors]))
    f.write('''

#ifdef __cplusplus
}
#endif


#endif // ARM_UC_MM_DER_MANIFEST_ACCESSORS_H
''')


with open(os.path.join(outputDir, 'arm_uc_mmDERManifestAccessors_autogen.c'), 'w') as f:
    f.write(FileHeaderBlock+'\n')
    f.write('''#include "arm_uc_mmDERManifestParser_autogen.h"
#include "arm_uc_mmDERManifestAccessors_autogen.h"
#include "update-client-manifest-types.h"
#include <stdio.h>

''')
    f.write('\n'.join([x['definition'] for x in Accessors])+'\n')
