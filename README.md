## Update manifest creation

### Manifest tool

The manifest tool creates and parses manifest files. You can use it as a command-line utility or Python package.

### Prerequisites

Some platforms require `python-dev` or `python3-dev` to install Python's cryptography library, which is a dependency of the manifest tool. For example, on Ubuntu, run:

```sh
$ sudo apt-get install python-dev
```

### Installation

The manifest tool is compatible both with Python 2.7.11 and later and with Python 3.5.1 and later.

There are 3 options for installing the manifest tool, but all use `pip`:

1. Install from GitHub over HTTPS.

    ```
        $ pip install git+https://github.com/ARMmbed/manifest-tool.git
    ```

1. Install from GitHub over SSH.

    ```
        $ pip install git+ssh://git@github.com/ARMmbed/manifest-tool.git
    ```

1. Install from a local copy of this repository.

    ```
        $ pip install .
    ```

<span class="notes">**Note:** This repository includes `setup.py`, but it does not work on all systems. Please use `pip` for the best experience.</span>

See [Debugging Installation](#debugging-installation) if these steps do not work.

### Workflow

The update client workflow has three stages:

1. Send a payload to an update medium, for example a web service, a removable storage device or a broadcast system.
1. Create a manifest for that payload. The manifest includes the hash and size of the payload along with its URI on the update medium.
1. Send that manifest to an update medium.

### Quick Start

In a new project that will support the update client, run the following command:

```
$ manifest-tool init -d "<company domain name>" -m "<product model identifier>" -a "<Mbed Cloud API Key>" -S "<Mbed Cloud Alternative API address>"
```

Note that you do not need to enter `-S` for the production environment.

The manifest tool is able to use the Mbed Cloud Python SDK to upload firmware and manifests to Mbed Cloud. If you do not require this feature, you can call `manifest-tool init` with fewer arguments:

```
$ manifest-tool init -d "<company domain name>" -m "<product model identifier>"
```

This will create several files:
* A certificate in `.update-certificates/default.der`.
* A matching private key in `.update-certificates/default.key.pem`.
* A set of default settings in `.manifest_tool.json`.
* Mbed Cloud settings in `.mbed_cloud_config.json`.

The default settings include:
* A unique vendor identifier, based on the domain name supplied to `init`.
* A unique model identifier, based on the vendor identifier and the model name supplied to `init`.
* The path of the certificate and private key.

If you do not want to enter the subject information for your certificate (country, state, city, organization and so on), add the `-q` flag to the command above.

<span class="notes">**Note:** The certificate created in `manifest-tool init` is not suitable for production. You should avoid using it except in testing and development. To create a certificate for production purposes, please use an air-gapped computer or a Hardware Security Module. You should conduct a security review on your manifest signing infrastructure, since it is the core of the security guarantees for update client.</span>

#### Single-device update
Once you have run `manifest-tool init`, you can perform updates on a single device by:

```sh
$ manifest-tool update device -p <payload> -D <device ID>
```

This will perform several actions:
1. Upload the payload to Mbed Cloud.
1. Hash the payload and create a manifest that links to its location in Mbed Cloud.
1. Create an update campaign for the supplied device ID, with the newly created manifest.
1. Start the campaign.
1. Wait for the campaign to complete.
1. Delete the payload, manifest and update campaign out of Mbed Cloud.

This allows development with a device for testing purposes.

#### Multidevice update
If more than one device needs updating, you can use the Mbed Cloud portal to create device filters that can include many devices into an update campaign. First, you need a manifest. Once you have run `manifest-tool init`, you can create manifests by:

```
$ manifest-tool update prepare -p <payload>
```

Optionally, a name and description for the payload and corresponding manifest can be provided:

```
$ manifest-tool update prepare -p <payload> -n <PAYLOAD_NAME> -d <PAYLOAD_DESCRIPTION>\
    --manifest-name <MANIFEST_NAME> --manifest-description <MANIFEST_DESCRIPTION>
```

Both methods of creating a manifest use the defaults created in `manifest-tool init`. You can override each default using an input file or command-line arguments. See below for more details.

Once `manifest-tool update prepare` has been executed the manifest file is automatically uploaded to Mbed Cloud and you can then create and start an update campaign using the Mbed Cloud portal.

### Debugging Installation

Some platforms require `python-dev` or `python3-dev` to install Python's cryptography library, which is a dependency of the manifest tool. For example, on Ubuntu, run:

```sh
$ sudo apt-get install python-dev
```

### Advanced usage
The manifest tool allows for significantly more flexibility than the model above shows. You can override each of the defaults that `manifest-tool init` sets by using the command-line or an input file. The manifest tool supports a variety of commands. You can print a full list of commands by using `manifest-tool --help`.

#### Prerequisites

To create a manifest, you must provide an ECC certificate and private key. The certificate must be an ECC secp256r1 DER encoded certificate. Best practice is for an authority the target device trusts to sign this certificate.

The update client on the target device must have this certificate available, or the certificate must be signed by a certificate that is available on the target device.

##### Creating a certificate for production use
To use a certificate in production, please use a Hardware Security Module or an air-gapped computer to create the certificate. You can then use this device to create signatures for manifests. If you use certificate delegation, you can use the HSM or air-gapped computer to sign the delegated certificates. You should perform a security review on your signing infrastructure.

##### Creating a certificate for development use
**For testing and evaluation only**

Providing a self-signed certificate is adequate for testing purposes. There are many methods for creating a self-signed certificate. The manifest tool provides two commands: `init` and `cert create`, which creates a self-signed certificate. OpenSSL can also produce one, but we do not recommended this on Mac OS X, due to the old version of OpenSSL that ships with it, nor on Windows, because you must install OpenSSL separately.

###### Creating a self-signed certificate with manifest-tool init
Running `manifest-tool init` in a project for the first time also creates a self-signed certificate. If a certificate already exists in `.update-certificates/default.der`, then no certificate is created. If you already have a certificate and private key, you should pass those in to `manifest-tool init` using the `-c <certificate-file>` and `-k <private key>` arguments.

###### Creating a self-signed certificate with manifest-tool cert create
The manifest tool provides a certificate creation command, which creates a self-signed certificate:

```
manifest-tool cert create -V <valid time> -K <private key output file> -o <certificate file>
```

In addition, you can provide subject arguments on the command-line to specify the country, state, locality, organization name and common name of the certificate's subject.

###### Creating a self-signed certificate with OpenSSL

Using OpenSSL, you can create a self-signed ECC certificate, but there are several caveats:

* OpenSSL defaults to SHA1 on many platforms, which is unsecure.
* On some platforms, it is not possible to specify SHA256.
* OpenSSL does not support ECC on some platforms.

**Unless the version of OpenSSL your platform provides is at least 1.0.1, we do not recommend you use OpenSSL.**

In order to generate a self-signed certificate, follow these steps:

```
openssl ecparam -genkey -name prime256v1 -out key.pem
openssl req -new -sha256 -key key.pem -out csr.csr
openssl req -x509 -sha256 -days 365 -key key.pem -in csr.csr -outform der -out certificate.der
```

<span class="notes">**Note:** `prime256v1` is an alias for `secp256r1`.</span>

Now, verify that OpenSSL used SHA256 to sign the certificate. Some OpenSSL installations ignore the `-sha256` parameter and create a SHA1 signature. This is a problem because of the deprecation of SHA1 due to weak security.

```
openssl req -in csr.csr -text -noout | grep -i "Signature.*SHA256"
```

#### Examining a certificate

To view the information in a certificate, use OpenSSL's x509 command:

```
openssl x509 -inform der -in certificate.der -text -noout
```

#### Obtaining a certificate fingerprint

The manifest tool fingerprints certificates during the manifest creation process. If you used `manifest-tool init`, then it is not necessary to extract the fingerprint.

You can use OpenSSL to check the manifest-tool's output or to obtain the certificate fingerprint if `manifest-tool init` was not used:

```
openssl x509 -inform der -in certificate.der -sha256 -fingerprint -noout
```

OpenSSL reports the fingerprint of the certificate:

```
SHA256 Fingerprint=00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F
```

When a C byte array is a requirement (for example, in the update client's certificate manager), this must be converted to one, for example by finding all `:` and replacing with `, 0x`.

```
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
```

This can be done in an automated way on systems that support the `sed` command. For example:

```
openssl x509 -inform der -in certificate.der -noout -fingerprint -sha256 | sed -e "s/.*=\(.*\)/\1/" | sed -e "s/:/, 0x/g" | sed -e "s/\(.*\)/uint8_t arm_uc_default_fingerprint[] = {0x\1};/"
uint8_t arm_uc_default_fingerprint[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
```

To turn the certificate itself into a byte array, use `xxd` or a similar tool for printing hexadecimal values:

```
xxd -i certificate.der
```

The manifest tool automates this process as part of the `init` command and places the output in `update_default_resources.c`.

#### Creating manifests

There are three ways to provide data to the manifest tool. It parses a JSON input file, which can contain all of the information used to create the manifest. If information is missing from the input file, the manifest tool checks for a file that contains defaults in the current working directory (`.manifest_tool.json`). You can create this file most easily using `manifest-tool init`. The third way of providing data is command-line arguments; you can override many of the fields the manifest tool uses on the command-line.

Currently, you need manifests to use SHA256 for hashes, ECDSA signatures on the secp256r1 curve, with no encryption. The manifest tool calls this encryption mode `none-ecc-secp256r1-sha256`. Future versions of the manifest tool will add support for payload encryption.

<span class="notes">**Note:** The Update client currently only supports binary payloads, so the payload type is assumed to be binary.</span>

##### Mode none-ecc-secp256r1-sha256

###### Minimum requirements for none-ecc-secp256r1-sha256
The minimum requirements for creating a manifest with unencrypted payload are:

* The cryptographic mode to use (none-ecc-secp256r1-sha256, in this case).
* The payload URI.
* One of:
    * The URI of a certificate to be used for signing the manifest.
    * A local file that is a certificate to be used for signing the manifest.
* A local file that is the signing key for that certificate.
* One of:
    * The vendor ID and device class ID.
    * The device ID.

###### What mode none-ecc-secp256r1-sha256 does

In this mode, the manifest tool creates and signs a manifest; the payload is unencrypted. The target device(s) must already have the provided certificate or must provide a way to fetch that certificate.

The manifest tool:

1. Fetches and hashes the payload. It loads the payload from a local file.
1. Fetches and fingerprints the certificate (either from the provided URI or the local file).
1. Creates the inner part of the manifest, containing:
    1. The provided IDs.
    1. The payload URI.
    1. The payload size.
    1. The payload hash.
1. Hashes the inner part of the manifest.
1. Uses the hash and the certificate private key to sign the inner part of the manifest.
1. Wraps the inner part, hash, signature, certificate fingerprint and certificate URI in the outer part of the manifest.

###### Using mode none-ecc-secp256r1-sha256

When you invoke the manifest tool to create a manifest with encryption mode `none-ecc-secp256r1-sha256`, the information below must be provided. The manifest tool can find most of the information in more than one way. You can provide every item in the input file. Alternative options are provided in parentheses.

* The type of hashing, signing and encryption to use (calculated from mandatory inputs if absent).
* Vendor ID (extracted from defaults if absent).
* Class ID (extracted from defaults if absent).
* Payload URI (overridden by `-u`).
* Payload File (overridden by `-p`).
* Description (defaults to empty).
* Certificate used for signing (extracted from defaults if absent).

###### Example 1:

Providing all fields by using the input file:

```JSON
{
    "encryptionMode" : "none-ecc-secp256r1-sha256",
    "vendorId" : "<hex representation of the 128-bit RFC4122 GUID that represents the vendor>",
    "classId" : "<hex representation of the 128-bit RFC4122 GUID that represents the device class>",
    "payloadUri" : "http://path.to/payload.bin",
    "payloadFile" : "/path/to/payload.bin",
    "description" : "Description of the update",
    "certificates": [
        { "uri": "http://path.to/certificate.der" , "file" : "/path/to/certificate.der" }
    ]
}
```

To create a manifest with this information, call the manifest tool:

```sh
$ manifest-tool create -i input.json -o output.manifest -k certificate_key.pem
```

###### Example 2:

Providing no input file. Run this command one time in the root of the project:

```sh
$ manifest-tool init -d "<company domain name>" -m "<product model identifier>"
```

Then, use this command to prepare an update:

```sh
$ manifest-tool create -u <url> -p <payload> -o <manifest file>
```

#### Manifest creation input file
If a `.manifest_tool.json` file is present in the current working directory when you run `manifest-tool create`, `manifest-tool update prepare` or `manifest-tool update device`, the manifest tool loads default values from this file. It overrides these values with the contents of the manifest creation input file. Then, it uses any command-line options to override the contents of the manifest creation input file. If you have used `manifest-tool init` to initialize the current working directory and you use `manifest-tool create -p <payload file> -u <url>`, then the input file is optional.

This means that all fields in the manifest creation input file are optional. However, the `.manifest_tool.json` defaults file, the manifest creation input file or the command-line must specify some fields:

1. `vendorId`.
1. `classId`.
1. `payloadUri`.
1. `payloadFile` or `payloadHash`.
1. `certificateFingerprint` or `certificateFile`.
1. `privateKey`.

The manifest creation input file follows the JSON representation of the [manifest format v1 specification]. Because there is a significant quantity of nesting in the input fields, there are short-hands for most fields.

Several parts in a nested structure comprise the manifest creation input file:

1. Signed resource.
    1. Manifest.
        1. Encryption info.
        1. Payload info.
    1. Signature block.

##### Signed resource

The signed resource is the top level object in the input file. Because of this, its name does not appear. It contains only two objects:

1. Manifest.
1. Signature block.

```JSON
{
    "resource" : {
        "resource" : {
            "manifest" : <the manifest object is inserted here>
         }
    },
    "signature" : <The signature object is inserted here>
}
```

* `manifest`: See the [Manifest] section.
* `signature`: See the [Signature block] section.

If you wish to use short-hand parameters, you must place them at this level, within the `SignedResource` object (the un-named top-level JSON object). For example, to use the shorthand for specifying a payload hash, add the `payloadHash` short-hand as below:

```JSON
{
    "resource" : {
        "resource" : {
            "manifest" : <the manifest object is inserted here>
         }
    },
    "payloadHash" : <hex-encoded payload hash>,
    "signature" : <The signature object is inserted here>
}
```

The full list of short-hand parameters is available in [Short-hand parameters].

##### Manifest
The manifest object contains several fields and one subobject.

```JSON
{
    "payload": <The payload object is installed here>,
    "description": "Description of the update",
    "vendorId": <hex representation of the 128-bit RFC4122 GUID that represents the vendor>,
    "classId": <hex representation of the 128-bit RFC4122 GUID that represents the device class>,
    "applyImmediately": true,
    "encryptionMode": {
        "enum": "none-ecc-secp256r1-sha256"
    },
    "vendorInfo": <Arbitrary data>
}
```

* `payload`: See the [Payload] section.
* `description`: A free-text description of the payload. This should be small.
* `vendorId`: Hex representation of the 128-bit RFC4122 GUID that represents the vendor.
* `classId`: Hex representation of the 128-bit RFC4122 GUID that represents the device class that the update targets. Device classes can mean devices of a given type (for example, smart lights) or model numbers. This allows targeting of updates to particular groups of devices based on the attributes they share, where a device class represents each set of attributes. Because of this, each device can have multiple device classes. Mbed Cloud Update Client only supports the use of device classes to represent model numbers/revisions.
* `applyImmediately`: This is always assumed to be true. Mbed Cloud Update Client does not currently implement it.
* `encryptionMode`: Mbed Cloud Client only supports one value:
    * `none-ecc-secp256r1-sha256`: SHA256 hashing, ECDSA signatures, using the secp256r1 curve. This does not use payload encryption.
* `vendorInfo`: You can place proprietary information in this field. We recommend DER encoding because this allows you to reuse the update client's general purpose DER parser.

##### Payload
The payload section describes the payload object.

```JSON
{
    "storageIdentifier": <numeric identifier for where to store the payload>,
    "reference": {
        "hash": <hex representation of the SHA256 hash of the payload>,
        "size": <size of the payload>,
        "uri": "http://path.to/payload",
        "file": <path to the payload file>
    }
}
```

* `storageIdentifier`: A number that the device recognizes for where to store the payload.
* `hash`: The SHA256 hash of the payload.
* `size`: The size of the payload.
* `uri`: The URI from which the target devices should acquire the payload.
* `file`: A path to a local copy of the payload. The manifest tool uses this file to calculate the payload hash and payload size. This is not needed if you specify the payload hash and size in the input file.

##### Signature block
Use the signature block to select the certificate the device should use to verify the signature of the manifest.

```JSON
{
    "signatures": [
        {
            "certificates": [
                {
                    "uri": "",
                    "fingerprint": "<hash of the inner part of the certificate>",
                    "file": "/path/to/certificate.der"
                }
            ]
        }
    ]
}
```

* `certificates`: A list of URI/fingerprint pairs. The first certificate in the list must match the private key that you provied to the manifest tool to sign the manifest, supplied through the `-k` command-line option. Each certificate must sign the certificate before it in the list. The last certificate in the list should be the root of trust in the device and can have an empty URI. Instead of a `fingerprint`, you can provide a `file` and the manifest tool will calculate the fingerprint. Note that Mbed Cloud Update Client does not provide a mechanism to fetch certificates in this list. Implementing this feature requires the developer to override `arm_uc_kcm_cert_fetcher`. By default, Mbed Cloud Update Client expects to have one certificate and that this certificate must verify all manifests.

##### Short-hand parameters

* `encryptionMode`: Sets the `encryptionMode` in `manifest`.
* `payloadFile`: Sets the `file` in `payload`.
* `payloadUri`: Sets the `uri` in `payload`.
* `payloadHash`: Sets the `hash` in `payload`.
* `payloadSize`: Sets the `size` in `payload`.
* `vendorInfo`: Sets the `vendorInfo` in `manifest`.
* `vendorId`: Sets the `vendorId` in `manifest`.
* `classId`: Sets the `classId` in `manifest`.
* `description`: Sets the `description` in `manifest`
* `certificates`: Sets the `certificates` in `signature`.

You can also override many of these parameters on the command-line. See `manifest-tool create --help` for more information.

#### Parsing manifests

##### Command-line

To convert a manifest to JSON:

```sh
manifest-tool parse -i input.manifest
```

To make the JSON more readable, use the `-j` flag.

```sh
manifest-tool parse -ji input.manifest
```

##### Python library

To convert a manifest file to a Python dictionary:

```
import manifesttool.parse

manifest = open('test0.manifest', 'rb').read()
parsed_manifest = manifesttool.parse.parseManifest(manifest)
print(parsed_manifest)
```

### Development

Install all required packages, and create a virtual environment:

```
pip2 install virtualenv
mkdir -p ~/virtualenvs
virtualenv ~/virtualenvs/manifest-tool
source ~/virtualenvs/manifest-tool/bin/activate
```
