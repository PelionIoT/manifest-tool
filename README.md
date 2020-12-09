# Device Management manifest CLI tool

This document explains how to install and use the manifest tool.

- [Manifest tool overview](#manifest-tool-overview)
- [Installing the manifest tool](#installing-the-manifest-tool)
- [Using the manifest tool](#using-the-manifest-tool)
- [Developer workflow example](#developer-workflow-example)
- [Troubleshooting](#troubleshooting)

<span class="notes">**Note:** Please see the [changelog](./changelog.md) for the list of all changes between release versions.</span>

## Manifest tool overview
Device Management lets you perform Firmware Over-the-Air (FOTA) updates
on managed devices.

On the device side, the firmware update process begins when the device
receives an update manifest. The OEM (original equipment manufacturer)
or update author cryptographically signs the manifest with a private key
paired to a public key that exists on the device, enabling the device to
authenticate the manifest before it accepts the firmware update.

Device Management supports:

* Full updates - Deliver new firmware and install it on the device.
* Delta updates - The manifest tool executes a diff algorithm that
  produces a small delta patch file. The nano client constructs a new
  firmware image based on the delta patch file and the firmware
  currently present on the device. This technique saves traffic
  bandwidth.

The `manifest-tool` Python package includes these command line tools:

- [`manifest-tool`](#manifest-tool) - Creates manifest files.
- [`manifest-delta-tool`](#manifest-delta-tool) - Generates delta patch
  files.
- [`manifest-dev-tool`](#manifest-dev-tool) - A developer tool for
  running a simplified update campaign.

## Installing the manifest tool

We recommend installing the `manifest-tool` Python package in a
[Python virtual environment](#creating-a-virtual-environment).

### Installing from PyPi

**Prerequisites:**

* [Python 3.5 or higher](https://www.python.org/downloads/).
* [pip (Python Package Installer)](https://pip.pypa.io/en/stable/).
* Internet connectivity

**To install the manifest tool from [PyPi](https://pypi.org/), run:**

```
pip install manifest-tool
```

### Installing from local source tree

**Prerequisites:**

* [Python 3.5 or later](https://www.python.org/downloads/).
* [pip (Python Package Installer)](https://pip.pypa.io/en/stable/).
* Native toolchain:
    * GCC/Clang for Linux/MacOS.
    * Microsoft Visual Studio 2017 or later for Windows.

**To install the manifest tool from the local source tree, run:**

1. Clone the PelionIoT/manifest-tool repository to your machine:  

    ```
    $ git clone https://github.com/PelionIoT/manifest-tool.git
    ```

1. Run:

    ```
    $ pip install <manifest-tool>
    ```

    Where `<manifest-tool>` is the path to the local source tree.

<span class="notes">**Note:** Run `$ pip install -e <manifest-tool>` to install the package in Python setuptools development mode. For more information, please see the [setuptools development mode documentation](https://setuptools.readthedocs.io/en/latest/setuptools.html#development-mode).</span>

### Creating a virtual environment

The `virtualenv` tool creates isolated Python environments, which are
useful in overcoming Python package collision issues when you work on
multiple projects. For more information, please see the
[Python documentation](https://docs.python.org/tutorial/venv.html).

**To create a virtual environment, run:**

```shell
$ virtualenv -p python3 venv  
```

**To activate the virtual environment in the current shell, run:**

```shell
$ source venv/bin/activate
```

## Using the manifest tool

This section explains how to use the CLI tools included in the
`manifest-tool` Python package:

- [manifest-tool](#manifest-tool)
- [manifest-delta-tool](#manifest-delta-tool)
- [manifest-dev-tool](#manifest-dev-tool)
- [Developer workflow example](#developer-workflow-example)

### manifest-tool

`manifest-tool` commands:

- [`manifest-tool create`](#manifest-tool-create) - Creates manifests.
- [`manifest-tool create-v1`](#manifest-tool-create-v1) - Creates V1
  schema-compatible manifests.
- [`manifest-tool parse`](#manifest-tool-parse) - Parses and verifies
  existing manifest files.
- [`manifest-tool schema`](#manifest-tool-schema) - Shows bundled input
  validation schema.
- [`manifest-tool public-key`](#manifest-tool-public-key) - Generates an
  uncompressed public key.

<span class="notes">**Note:** Run `manifest-tool --help` for more information about all commands, or `manifest-tool <command> --help` for more information about a specific command, including its parameters and how to use them.</span>

#### `manifest-tool create`

Creates a manifest. The manifest tool receives a configuration file
describing the update type.

**Prerequisites**

* An update private key and public key certificate.

    Keep the private key secret because it allows installing new
    firmware images on your devices.

    Provision the public key to the device.

    * To generate a private key, run:

        ```shell
        $ openssl ecparam -genkey -name prime256v1 -outform PEM -out my.priv.key.pem
        ```

  *   To generate a public key in uncompressed point format (X9.62), use
      the [`manifest-tool public-key`](#manifest-tool-public-key)
      command.

* Upload the new firmware binary to a server that the device you want to
  update can reach, and obtain the URL for the uploaded firmware binary.

* A configuration file in JSON or YAML format.

    Configuration file format:
    ```yaml
    vendor:  # One of "domain" or "vendor-id" fields are expected
      domain: pelion.com  # FW owner domain. Expected to include a dot (".")
      vendor-id: fa6b4a53d5ad5fdfbe9de663e4d41ffe  # Valid vendor UUID
    device:  # One of "model-name" or "class-id" fields are expected
      model-name: Smart Slippers  # A device model name
      vendor-id: fa6b4a53d5ad5fdfbe9de663e4d41ffe  # Valid device-class UUID

    priority: 1  #  Update priority as will be passed to authorization callback
                 #  implemented by application on a device side
    payload:
      url: http://some-url.com/files?id=1234  # File storage URL for devices to
                                              # acquire the FW candidate
      file-path: ./my.fw.bin  # Update candidate local file - for digest
                              # calculation & signing
      format: raw-binary  # one of following:
                          #  raw-binary - for full image update
                          #  arm-patch-stream - for differential update
    component: MAIN  # [Optional] Component name - only relevant for manifest v3 format.
                     # If omitted "MAIN" component name will be used for updating
                     # the main application image
    sign-image: True  # [Optional] Boolean field accepting True/False values - only
                      # relevant for manifest v3 format.
                      # When Set to True - 64 Bytes raw signature over the installed
                      # image will be added to the manifest.
                      # Image signature can be used for cases when device bootloader
                      # expects to work with signed images (e.g. secure-boot)
                      # When omitted False value is assumed
    ```
**Example**

* For this configuration file, called `my.config.yaml`:

    ```yaml
    vendor:
      domain: pelion.com
    device:
      model-name: Smart Flip-flops
    priority: 1
    payload:
      url: http://some-url.com/files?id=1234
      file-path: ./my.fw.bin
      format: raw-binary
    ```

* Run:

    ```shell
    manifest-tool create \
        --config my.config.yaml \
        --key my.priv.key.pem \
        --fw-version 1.2.3 \
        --output my.manifest.bin
    ```

#### `manifest-tool create-v1`

Older versions of Device Management FOTA update client use manifest
schema V1 and assume the public key is packaged in a x.509 certificate.

**Prerequisites**

* An update private key and public key certificate.

    Keep the private key secret because it allows installing new
    firmware images on your devices.

    Provision the public key to the device.

    * To generate a private key, run:

        ```shell
        $ openssl ecparam -genkey -name prime256v1 -outform PEM -out my.priv.key.pem
        ```
    * To generate a public key x.509 certificate, run:

        ```shell
        $ openssl req -new -sha256 \
              -key my.priv.key.pem \
              -inform PEM \
              -out my.csr.csr
        $ openssl req -x509 -sha256 \
              -days 7300 \
              -key my.priv.key.pem \
              -in my.csr.csr \
              -outform der \
              -out my.x509.certificate.der
        ```

        <span class="notes">**Note:** Device Management FOTA treats the x.509 certificate as a container **ONLY** and does not enforce its validity - expiration, chain of trust, and so on - although it may be validated by other Device Management components. For production, we recommend creating a certificate with a lifespan greater than the product's expected lifespan (for example, 20 years).</span>

**Example**

* For this configuration file, called `my.config.yaml`:

    ```yaml
    vendor:
      domain: pelion.com
    device:
      model-name: DUT.my.device
    priority: 1
    payload:
      url: http://some-url.com/files?id=1234
      file-path: ./my.fw.bin
      format: raw-binary
    ```

* Run:

    ```shell
    manifest-tool create-v1 \
        --config my.config.yaml \
        --key my.priv.key.pem \
        --update-certificate my.x509.certificate.der \
        --output my.manifest.bin
    ```

#### `manifest-tool parse`

Parses and validates existing manifest files.

**Prerequisites**

* A manifest file (in our example `my.manifest.bin`).
* Optionally, an update private key or public key or certificate to
  validate the manifest signature.

**Example**

```shell
$ manifest-tool parse \
  my.manifest.bin \
  --private-key my.priv.key.pem
----- Manifest dump start -----
Manifest:
vendor-id=fa6b4a53d5ad5fdfbe9de663e4d41ffe
class-id=3da0f138173350eba6f665498eace1b1
update-priority=15
payload-version=1572372313
payload-digest=b5f07d6c646a7c014cc8c03d2c9caf066bd29006f1356eaeaf13b7d889d3502b
payload-size=512
payload-uri=https://my.server.com/some.file?new=1
payload-format=raw-binary
----- Manifest dump end -----
2019-10-29 20:05:13,478 INFO Signature verified!
```

#### `manifest-tool schema`

Prints the input validation JSON schema bundled with the current tool.
The manifest tool contains an input validation schema, which you can use
as a self-documenting tool to better understand and validate the
manifest tool input configuration.

**Example**

```shell
$ manifest-tool schema
```
Output:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Manifest-tool input validator",
  "description": "This schema is used to validate the input arguments for manifest-tool",
  "type": "object",
  "required": [
    "vendor",
    "device",
    "priority",
    "payload"
  ],
  "properties": {
    "vendor": {
      "type": "object",
      "properties": {
        "domain": {
          "$ref": "#/definitions/non_empty_string",
          "description": "Vendor Domain",
          "pattern": "\\w+(\\.\\w+)+"
        },
        "vendor-id": {
          "$ref": "#/definitions/uuid_hex_string",
          "description": "Vendor UUID"
        },
        "custom-data-path": {
          "$ref": "#/definitions/non_empty_string",
          "description": "Path to custom data file  - must be accessible by the manifest-tool"
        }
      },
      "oneOf": [
        {"required": ["domain"]},
        {"required": ["vendor-id"]}
      ]
    },
    "device": {
      "type": "object",
      "properties": {
        "model-name": {
          "$ref": "#/definitions/non_empty_string",
          "description": "Device model name"
        },
        "class-id": {
          "$ref": "#/definitions/uuid_hex_string",
          "description": "Device class UUID"
        }
      },
      "oneOf": [
        {"required": ["model-name"]},
        {"required": ["class-id"]}
      ]
    },
    "priority": {
      "description": "Update priority",
      "type": "integer"
    },
    "payload": {
      "type": "object",
      "required": [
        "url",
        "format",
        "file-path"
      ],
      "properties": {
        "format": {
          "description": "Payload format type",
          "enum": [
            "raw-binary",
            "arm-patch-stream"
          ]
        },
        "url": {
          "$ref": "#/definitions/non_empty_string",
          "description": "Payload URL in the cloud storage"
        },
        "file-path": {
          "$ref": "#/definitions/non_empty_string",
          "description": "Path to payload file - must be accessible by the manifest-tool"
        }
      }
    },
    "component": {
      "description": "Component name - only relevant for manifest v3",
      "$ref": "#/definitions/non_empty_string"
    },
    "sign-image":{
      "description": "Do sign installed image - only relevant for manifest v3. Required for devices with PKI image authentication in bootloader",
      "type": "boolean"
    }
  },
  "definitions": {
    "non_empty_string": {
      "type": "string",
      "minLength": 1
    },
    "uuid_hex_string": {
      "type": "string",
      "pattern": "[0-9a-fA-F]{32}",
      "description": "HEX encoded UUID string"
    }
  }
}
```

<span class="notes">**Note:** This schema is an example captured for manifest-tool version 2.0. Make sure to execute the `manifest-tool schema` command on your machine to get the up-to-date schema for your installed tool version.</span>

#### `manifest-tool public-key`

Creates a public key file containing a key in uncompressed point format
(X9.62). Provisioning this file to the device enables the device to
verify the manifest signature.

**Example**

```shell
manifest-tool public-key my.priv.key.pem --out my.pub.key.bin
```

### manifest-delta-tool

Use this tool to generate delta patch files for delta updates.

Run `manifest-delta-tool --help` for more information about usage and
arguments.

**Prerequisites**

* The firmware currently installed on the device and the updated
  firmware image. Required for calculating the delta patch.

**Example**

```shell
$ manifest-delta-tool -c current_fw.bin -n new_fw.bin -o delta-patch.bin
```

<span class="notes">**Note 1:** Compression block size has a direct impact on the amount of memory required by the device receiving the update. The device requires twice the amount of RAM in runtime to decompress and apply the patch.</span>

<span class="notes">**Note 2:** Compression block must be aligned with network (COAP/HTTP) buffer size used for download. Misalignment in sizes may result in device failure to process the delta patch file.</span>

### manifest-dev-tool

`manifest-dev-tool` is a developer tool for running a simplified update
campaign.

Use `manifest-dev-tool` for development flows only.

`manifest-dev-tool` commands:
- [`manifest-dev-tool init`](#manifest-dev-tool-init) - Initializes the
  developer environment.
- [`manifest-dev-tool create`](#manifest-dev-tool-create) - Simplified
  tool for creating manifests.
- [`manifest-dev-tool create-v1`](#manifest-dev-tool-create-v1) -
  Simplified tool for creating manifests using the V1 schema.
- [`manifest-dev-tool update`](#manifest-dev-tool-update) - Lets you
  perform end-to-end tests without leaving the command shell.
- [`manifest-dev-tool update-v1`](#manifest-dev-tool-update-v1) - Lets
  you perform end-to-end tests without leaving the command shell using a
  V1-schema manifest.

<span class="notes">**Note:** Run `manifest-dev-tool --help` for more information about all commands, or `manifest-dev-tool <command> --help` for more information about a specific command, including its parameters and how to use them.</span>

#### `manifest-dev-tool init`

Initializes the developer environment:
* Creates an update private key and a public key certificate.
* Generates a `fota_dev_resources.c` file with symbols that allow
  bypassing the provisioning step in the developer flow.
* Creates configuration files, which you use when you run the
  [`manifest-dev-tool create`](#manifest-dev-tool-create) and
  [`manifest-dev-tool update`](#manifest-dev-tool-update) commands.

<span class="notes">**Note:** Only use the credentials the `manifest-dev-tool` tool generates in the development flow.</span>

**Example**

```shell
manifest-dev-tool init --force -a [API key from Device Management Portal]
```

#### `manifest-dev-tool create`

Creates developer manifest files without requiring an input
configuration file.

**Example**

```shell
manifest-dev-tool create \
    --payload-url http://test.pdmc.pelion.com?fileId=1256 \
    --payload-path new_fw.bin \
    --fw-version 1.2.3 \
    --output update-manifest.bin
```

<span class="notes">**Note:** To run a delta update, create the file specified in the `--payload-path` argument using the [`manifest-delta-tool`](#manifest-delta-tool) command. The file has the same name but a `.yaml` suffix (in the example, `new-fw.yaml` instead of `new-fw.bin`).</span>

<span class="notes">**Note:** Add the `--sign-image` argument to update a device with a secure bootloader, which requires an image signature.</span>

#### `manifest-dev-tool create-v1`

Creates developer manifest files in v1 format without requiring an input
configuration file.

**Example**

```shell
manifest-dev-tool create-v1 \
    --payload-url http://test.pdmc.pelion.com?fileId=1256 \
    --payload-path new-fw.bin \
    --output update-manifest.bin
```

<span class="notes">**Note:** To run a delta update, create the file specified in the `--payload-path` argument using the [`manifest-delta-tool`](#manifest-delta-tool) command. The file has the same name but a `.yaml` suffix (in the example, `new-fw.yaml` instead of `new-fw.bin`).</span>

#### `manifest-dev-tool update`

Same as [`manifest-dev-tool create`](#manifest-dev-tool-create) but also
lets you interact with Device Management Portal to run a full update
campaign on a single device.

The command:

1. Uploads the payload to Device Management Portal and obtains the URL.
2. Creates a manifest file with the URL from the previous step and
   obtains a manifest URL.
3. Creates an update campaign with the manifest URL from the previous
   step.
4. Starts the update campaign if you pass the `--start-campaign` or
   `--wait-for-completion` argument.
5. If you pass the `--wait-for-completion` argument, the tool waits for
   campaign completion for the time period specified by `--timeout` or
   until the campaign reaches one of its terminating states in Device
   Management Portal (`expired`, `userstopped`, or
   `quotaallocationfailed`).
6. If you pass the `--wait-for-completion` argument without the
   `--no-cleanup` flag, the tool removes the uploaded test resources
   from Device Management Portal before exiting. When you terminate the
   tool, the tool skips the cleanup step.

<span class="notes">**Note:** [`manifest-dev-tool init`](#manifest-dev-tool-init) creates the directory you specify in `--cache-dir`.</span>

**Example**

  ```shell
  manifest-dev-tool update \
      --payload-path my_new_fw.bin \
      --fw-version 1.2.3 \
      --wait-for-completion
  ```

<span class="notes">**Note:** The tool creates the device filter for the campaign based on the unique `class-id` and `vendor-id` fields the [`manifest-dev-tool init`](#manifest-dev-tool-init) command generates.</span>

#### `manifest-dev-tool update-v1`

Same as [`manifest-dev-tool update`](#manifest-dev-tool-update) with a
v1-format manifest.

**Example**

  ```shell
  manifest-dev-tool update-v1 \
      --payload-path my_new_fw.bin \
      --wait-for-completion
  ```

### Developer workflow example

1. Clone the https://github.com/PelionIoT/mbed-cloud-client-example
   repository.
2. From within the repository, execute:

    ```
    manifest-dev-tool init --force -a $MY_API_KEY
    ```
    The tool generates and compiles a `fota_dev_resources.c` file.

1. Flash the bootloader and firmware to the device.
1. Create a firmware update candidate.

    OR

    Create a delta-patch:
    ```
    manifest-delta-tool -c curr_fw.bin -n new_fw.bin -o delta.bin
    ```

1. Issue an update:

    ```
    manifest-dev-tool update --payload-path
    new_fw.bin --wait-for-completion
    ```
   For a delta update, the payload is `delta.bin`.

## Troubleshooting

* **Getting more context on unexpected errors.**  

   When the tool exits with a non-zero return code, it may be helpful to
   get more context on the failure.

   **Solution:** execute the tool with the `--debug` flag at the top
   argument parser level. For example:

   ```
   manifest-dev-tool --debug update
   ```

* **`manifest-dev-tool update ... --wait-for-completion` takes longer than expected.**

   `manifest-dev-tool update` creates a unique `class-id` and
   `vendor-id` generated per developer. Device Management expects a
   single device with these properties to connect to Device Management
   Portal.

   In rare cases, during development, a device's `device-id` might
   change after you re-flash it. This may result in two devices having
   the same `class-id` and `vendor-id` in Device Management Portal. In
   this scenario, Device Management will detect both devices and try to
   update them both, although one of them no longer exists

   **Solution:** Manually delete the unwanted device from Device
   Management Portal. Alternatively, run `manifest-dev-tool update ...
   --wait-for-completion` with `--device-id DEVICE_ID` to override the
   default campaign filter and target a specific device by its ID.

* **Update fails and `manifest-dev-tool update ...
  --wait-for-completion` cleans all resources.**

   You might want to leave the resources (firmware image candidate,
   update manifest and update campaign) on a service for further
   investigation/retry.

    **Solution:** Execute `manifest-dev-tool update ...
    --wait-for-completion` with the `--no-cleanup` flag.
