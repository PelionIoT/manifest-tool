## Update manifest format specification

This document explains the v1 manifest format.

### Forward-looking features

There are several forward-looking features and fields in this document that are not implemented in the manifest tool or the Device Management Update Client. We created these features for advanced use cases, so the manifest format would not require significant revisions after deployment.

### Manifest Format v1.0.0

Firmware updates on IoT devices pose several challenges: the update mechanism needs to be both private and trusted to prevent security breaches. Making the update process private requires encryption, and making it trusted requires cryptographic signatures from trusted parties. The format needs to be universal to cover most applications, but restricted enough that it is possible to test comprehensively.

The manifest format is agnostic of the update method – the same format covers updates through USB mass storage, DAPLink, server APIs, UART, ZigBee, BLE, Ethernet, TFTP+DHCP and Wi-Fi.

We designed the manifest format for content delivery networks, so you can store the payload and the corresponding manifests on untrusted servers or distributed through untrusted protocols, such as HTTP and TFTP. The manifest format also provides protection against man-in-the-middle attacks during the update (BLE and so on).

### Prerequisites

To use the manifest format, your IoT devices needs two things:

1. A private key.
1. The public key of a party that it trusts to distribute firmware updates.

### Data Organization

You can divide the information that an IoT device needs to validate, decipher and use an update into three broad categories: the encryption key, the cryptographic hash and signature and the manifest, which contains metadata and cryptographic information about the payload.

This format reduces complexity in IoT devices by using the same format as industry standard X.509 certificates: ASN.1's DER encoding.

The top-level document is a `SignedResource`. The signature must cover all data that influences interpretation or parsing of the `Resource`, which is why the `SignedResource` wraps the `Resource` rather than including a signature of just a `Manifest` or a `Payload` in the `Resource`.

The `Resource` also optionally may contain a URL.

```
SignedResource ::= SEQUENCE {
    resource  Resource,
    signature ResourceSignature
}

Resource ::= SEQUENCE {
    url     Url OPTIONAL,
    resourceType        ENUMERATED {
        manifest(0), payload(1)
    },
    resource CHOICE {
        manifest Manifest,
        payload Payload
    }
}
```

#### Signatures

Any time an actor in the system receives a manifest, the actor must verify it. An actor may be anyone or anything involved in sending an update to a device. For example, a device, a device manager, an Operator or a Firmware Author.

Good security practice suggests changing the keys you use to sign manifests from time to time. A high security key, typically stored in a Hardware Security Module or in an air-gapped computer, should, in turn, sign these keys. The process of signing a public key with a high security key creates a chain of trust that a receiving actor can use to validate a signature without directly trusting the signer. The process of changing keys means that a receiving actor may not recognize the key that has signed a manifest.

Typically, the keys directly used for signing are packaged in an X.509 certificate, which provides additional information about the key and its owner.

The receiving actor uses a single key to authenticate each signature - however, because the actor may not know the authentication key, the manifest must give a list of fingerprints or identifiers for the _keys_ that occur in the chain. The creator of the manifest must sign the manifest with the key identified by the first item in this list.

```
CertificateReference ::= SEQUENCE {
    fingerprints Bytes,
    url          Url
}
ResourceSignature ::= SEQUENCE {
    certificates SEQUENCE OF CertificateReference,
    signature   OCTET STRING
}
```

If the receiving actor recognizes any fingerprint in the `certificates` list, the actor can use this fingerprint to build up a chain of trust to the first fingerprint in the list, which is the one the actor must use to verify the manifest signature. The actor builds the chain of trust by fetching certificates from the URLs listed in the `certificates` list and then verifying the signature on each fetched certificate, starting with the last certificate in the list that the actor doesn't trust and ending with the certificate the actor uses to verify the manifest signature.

<span class="notes">**Note:** Certificate delegation (verifying a certificate that is signed by a trusted public key) is a forward-looking feature that Device Management Update Client does not support. You can implement it by overriding the certificate fetcher in the Device Management Update Client (`arm_uc_certificateStorer`).</span>

#### ResourceReferences

ResourceReferences are a container for specifying something that the manifest does not include. Any actor that validates the manifest (for example, a device targeted by the manifest, a Firmware Author validating a manifest or an Operator that is evaluating a new firmware image) uses the `url` to obtain the resource and the `hash` to validate its integrity. The hash is SHA256. Other hash types are not in this version, but later stages may include them.

The `dependencies` list and the `PayloadInfo` structure use ResourceReferences.

The `url` is optional. If the manifest author does not place a URL in the manifest, the actor validating the manifest must have access to the resource and be able to identify it by hash.

```ASN.1
ResourceReference ::= SEQUENCE {
    hash    OCTET STRING,
    url     Url OPTIONAL,
    size    INTEGER
}
```

#### Resource aliases

<span class="notes">**Note:** This is a forward-looking feature that the manifest tool and Device Management Update Client do not support.</span>

In complex environments, where you create a manifest that uses the `dependencies` list, you can use the `aliases` list to change where the target device looks to find a payload.

For example, if an Operator is distributing firmware that a device's OEM provides, but the Operator wants all the devices in the network to use its own infrastructure for fetching the firmware image, it:

1. Stores the OEM manifest in the Operator's infrastructure.
1. Creates an Operator manifest that contains:
    1. A dependency on the OEM manifest, consisting of:
        1. The hash of the OEM manifest.
        1. The URL of the OEM manifest in the Operator's infrastructure.
        1. The size of the OEM manifest.
    1. An alias to the Operator manifest that contains:
        1. The hash of the OEM firmware.
        1. The URL of the OEM firmware in the Operator's infrastructure.

When a device reads this manifest pair, it replaces URLs in ResourceReferences with those in aliases if they have a matching hash.

```ASN.1
ResourceAlias ::= SEQUENCE {
    hash        OCTET STRING,
    url         Url,
}
```

### Update manifest

The most important type of Resource is the manifest.

```
Manifest ::= SEQUENCE {
    manifestVersion     ENUMERATED {
      v1(1)
    },
    description UTF8String OPTIONAL,
    timestamp   INTEGER,
    vendorId    UUID,
    classId     UUID,
    deviceId    UUID,
    nonce       OCTET STRING,
    vendorInfo      OCTET STRING,
    precursorDigest OCTET STRING OPTIONAL,
    applyPeriod SEQUENCE {
        validFrom     INTEGER,
        validTo       INTEGER
    } OPTIONAL,
    applyImmediately    BOOLEAN,
    priority     INTEGER OPTIONAL,
    encryptionMode  CHOICE {
        enum    ENUMERATED {
            invalid(0),
            aes-128-ctr-ecc-secp256r1-sha256(1),
            none-ecc-secp256r1-sha256(2),
            none-none-sha256(3)
        },
        objectId    OBJECT IDENTIFIER
    },
    aliases         SEQUENCE OF ResourceAlias,
    dependencies    SEQUENCE OF ResourceReference,
    payload        PayloadDescription OPTIONAL
}


PayloadDescription ::= SEQUENCE {
    format      CHOICE {
        enum    ENUMERATED {
            undefined(0), raw-binary(1), cbor(2), hex-location-length-data(3), elf(4)
        },
        objectId    OBJECT IDENTIFIER
    },
    encryptionInfo SEQUENCE {
        initVector OCTET STRING,
        id CHOICE {
            key OCTET STRING,
            certificate CertificateReference
        },
        key      CHOICE {
           keyTable  Uri,
           cipherKey OCTET STRING
        } OPTIONAL
    } OPTIONAL,
    storageIdentifier UTF8String,
    reference    ResourceReference,
    installedSize INTEGER OPTIONAL,
    installedDigest OCTET STRING OPTIONAL,
    version     UTF8String OPTIONAL
}
```

Below are the field desriptions, organized by type:

#### Payload information

*   `manifestVersion` - This manifest's format version (of the manifest itself).
*   `description` - A free-text description of the update. Do not use this for validation or application of the manifest or payload.
*   `vendorId` - An RFC4122 UUID, identifying the vendor of the target device or software module in a modular system. The target must match this identifier if the manifest author has placed it in the manifest.
*   `classId` - An RFC4122 UUID, identifying the kind, model or version of device or software module. The target must match this identifier if the manifest author has placed it in the manifest.
*   `deviceId` - A RFC4122 UUID, uniquely identifying the target device. The target must match this identifier if the manifest author has placed it in the manifest. **Note:** The current Device Management Update Client does not support Device IDs.
*   `timestamp` - The creation timestamp of the manifest. This provides rollback protection for the root manifest for a given tree.
    *   This must be always increasing. It is forbidden for a device to install a payload with a version older or equal than its current version.
    *   If you require a rollback to an older payload version for stability purposes, you need to create a new update manifest for the old payload.
*   `nonce` - A 128-bit random field. The manifest tool provides this to ensure that the signing algorithm is safe from timing side-channel attacks.
*   `vendorInfo` - You can use this field to implement installation checks or installation instructions that are specific to your application. This is for extensions specific to narrow circumstances (for example, a door vendor might have a flag for "don't apply this update unless you're currently locked"). We recommend DER encoding because this allows the vendor to reuse the update client's general purpose DER parser.
*   `precursorDigest` - This field is used in delta updates to specify the image that must already be present on the device for the delta update to produce the correct result.
*   `applyImmediately` - This flag tells the target device to apply the manifest as soon as possible. If not set, the target device MUST not apply this update unless another manifest depends on the update. **Note:** The current Device Management Update Client release does not support this functionality. It ignores `applyImmediately`.
*   `validFrom` and `validTo` - Times between which it is acceptable for the target device to apply this update. Outside of these times, the target device MUST not apply this manifest (even if other manifests depend on it). **Note:** The current Device Management Update Client release does not support this functionality. It ignores `validFrom` and `validTo`.
*   `priority` - The importance of the update. This is an integer that is provided to an application-specific authorisation function. 0 typically means "mandatory" and increasing values have lower priority.
*   `dependencies` - References other manifests (other data types are an error). When a device applies this manifest, it must simultaneously apply all the manifests that this list references. **Note:** The current Device Management Update Client release does not support this functionality.
*   `payload` - Describes a payload for an IoT device to apply. See below for subproperties.
*   `aliases` - Allows a manifest to provide an alternate location for obtaining any payload or other manifest references. See [Resource aliases] for more information. **Note:** The current Device Management Update Client release does not support this functionality.

##### `PayloadDescription` properties

*   `format` - Either an enum (for compactness) or an ObjectID. If the target device does not understand this format, it will not apply the update. Current supported values are Raw Binary (1) and Stream-structured bsdiff with LZ4 compression (5).
*   `reference` - The hash (and optionally location or size) of the payload.
*   `version` - A human-readable (for UIs only, not used for validity checks) description of the payload version.
*   `storageIdentifier` - An identifier for the location of the payload.
*   `installedDigest` - Used in non-raw-binary updates to specify the result of applying an update. The digest in `reference` specifies the digest of the downloaded object. For non-raw-binary payloads, a second digest is needed to ensure that the result of any processing applied to the resource results in the correct payload image.
*   `installedSize` - Used in non-raw-binary updates to specify the size of an image after any processing is applied.

#### Encryption

*   `encryptionMode` - This describes the encryption configuration with which the payload that the manifest describes has been secured by the manifest's author. The `encryptionMode` defines the hash algorithm, the signing algorithm and the payload encryption algorithm (if any) that the manifest author has used.
*   `initVector` - Initialization vector for the AES engine. The `encryptionMode` decides the size. If `encryptionMode` specifies AES encryption, this field is mandatory.

##### Encryption Keys

<span class="notes">**Note:** The current Device Management Update Client release does not support this functionality.</span>

Encryption keys are always symmetric keys. A manifest author can choose to wrap encryption keys with other encryption keys, which means a target device can require multiple encryption keys to decrypt a payload.

If many devices share the payload, it is better for the manifest author to encrypt it only once, with a single key. The simplest solution for a single key is that all devices receiving the payload share it. However, if a device were to leak that single key, it would compromise all future updates. To improve this, the key used to encrypt the payload should be unique to each payload. This means that each device that receives the payload must be able to receive or derive a new key for each payload.

You can use one of these strategies to accomplish key distribution:

* The device manager delivers a key to every device in advance of the update.
* The manifest author encrypts the payload key and places it in the manifest. This requires the manifest author to generate one manifest for each target device. The manifest author can choose to encrypt the payload key using either of the following:
    * A preshared symmetric key.
    * A symmetric key derived with ECDH.
* The manifest author encrypts the payload key for each target device. The author collect pairs of device ID and ciphertext payload key for each device and bundle them into a table of keys. The author publishes the table in a way that is accessible to the target devices and places a reference to that table in the manifest. Each target device can decrypt only its own ciphertext payload key.
    * A preshared symmetric key.
    * A symmetric key derived using ECDH.

Several mechanisms can deliver preshared symmetric keys:

* The provisioning client.
* Compilation-time inclusion.
* A previous payload.
* The user application on the target device.

The Firmware Author may choose to build the device with the capacity to store several pre-shared keys. This means that the manifest must have a key identifier so that the device knows which preshared key to use. Similarly, the Firmware Author may choose to provide the device with the ability to store several certificates for the manifest author for use in encryption, so the manifest author must specify which certificate the end device should use with a certificate fingerprint.

Fields:

*   `id` - Either an OCTET STRING identifying the key to use or a CertificateReference identifying the certificate to use:
    *   `keyId` - This is the identifier for the decryption key. If `key` is not present, then the target device can use this key directly to decode the payload.
    *   `certificate` - This references the certificate that the receiving actor should use to perform offline-ECDH key agreement.
*   `key` - Either a cipherKey or a keyTable.
    *   `keyTable` - A reference to the key table for the payload. The receiving actor should only fetch the key table if the `keyId` value is familiar to the device.
    *   `cipherKey` - An encrypted payload key. The manifest author encrypts this key using either a symmetric algorithm with a per-device shared key, identified by the `keyId,` or with a key derived using public key cryptography, using a certificate that `certificate` designated.

### Dependencies and Permissions

Some authors have the authority to instruct the application of updates (by setting the `applyImmediately` flag). Additionally, only some authors have the authority to generate payloads.

These authorities might be separate (for example, manufacturer authors payloads and signs the manifest describing them, but only building manager can give the go-ahead to install after suitable testing). Having two manifests, one depending on the other, handles this:

```diagram
[Manifest with "applyImmediately" set, signed by building manager]
    |
    |--> [Manifest with payload, signed by manufacturer]
```

In the future, different components (for example, modules) might update separately to provide more protection for more critical or sensitive areas of code. In this case, the tree might branch:

```diagram
[Manifest with "applyImmediately" set, signed by building manager]
    |
    |--> [Manifest with main application payload, signed by manufacturer]
    |
    |--> [Manifest with mbed TLS update, signed by ARM]
    |
    |--> [WiFi chip update, signed by WiFi manufacturer]
```

This dependency-tree structure also makes it possible for different classes of device to share some components of an update, but differ on others:

```diagram
     /--> [update for X-Class devices only]
    /
[Manifest for X-Class devices]
    \
     |--> [update for common component, signed by manufacturer]
    /
[Manifest for Y-Class devices]
    \
     \--> [update for Y-Class devices only]
```
