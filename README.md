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
  produces a small delta patch file. The client constructs a new
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

We recommend installing the `manifest-tool` Python package in a isolated
[Python virtual environment](https://virtualenv.pypa.io).


### Installing the manifest tool from [PyPi](https://pypi.org/project/manifest-tool/)

**Prerequisites:**

* [Python 3.6 or higher](https://www.python.org/downloads/).
* [pip (Python Package Installer)](https://pip.pypa.io/en/stable/).
* Internet connectivity

```
pip install manifest-tool
```

### Installing from local source tree

**Prerequisites:**

* [Python 3.6 or later](https://www.python.org/downloads/).
* [pip (Python Package Installer)](https://pip.pypa.io/en/stable/).
* Native toolchain:
    * GCC/Clang for Linux/MacOS.
    * [Microsoft Build Tools for Visual Studio 2019](https://www.visualstudio.com/downloads/#build-tools-for-visual-studio-2019) for Windows or different version sutibule to your Python version as describe [here](https://wiki.python.org/moin/WindowsCompilers).

```
$ git clone https://github.com/PelionIoT/manifest-tool.git
$ pip install <path to manifest-tool's local source tree>
```

<span class="notes">**Note:** Run `$ pip install --editable <manifest-tool>` to install the package in Python setuptools development mode. For more information, please see the [setuptools development mode documentation](https://setuptools.readthedocs.io/en/latest/setuptools.html#development-mode).</span>


## Using the manifest tool

This section explains how to use the CLI tools included in the
`manifest-tool` Python package:

- [manifest-tool](#manifest-tool)
- [manifest-delta-tool](#manifest-delta-tool)
- [manifest-dev-tool](#manifest-dev-tool)

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

* Upload the new firmware binary to a server that your devices can access, and obtain the URL for the uploaded firmware binary.

* A configuration file in JSON or YAML format.

    Configuration file format:
    ```yaml
    vendor:  # One of "domain" or "vendor-id" fields are expected
      domain: pelion.com  # FW owner domain. Expected to include a dot (".")
                          # Will be used to generate a vendor UUID
      # or
      vendor-id: fa6b4a53d5ad5fdfbe9de663e4d41ffe  # Valid vendor UUID

    device:  # One of "model-name" or "class-id" fields are expected
      model-name: Smart Slippers  # A device model name
                                  # Will be used to generate a device-class UUID
      # or
      class-id: 327c726ac6e54f7a82fbf1d3beda80f0  # Valid device-class UUID

    priority: 1  #  Update priority as will be passed to authorization callback
                 #  implemented by application on a device side

    payload:
      url: http://some-url.com/files?id=1234  # File storage URL for devices to
                                              # acquire the FW candidate
      file-path: ./my.fw.bin  # Update candidate local file - for digest
                              # calculation & signing
      format: raw-binary  # one of following:
                          #  raw-binary - for full image update campaigns
                          #  arm-patch-stream - for delta update campaigns

    component: MAIN  # [Optional] The name of the component to be updated - only relevant for manifest v3 format.
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

Older versions of Device Management update client use manifest
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

        <span class="notes">**Note:** Device Management update client treats the x.509 certificate as a container **ONLY** and does not enforce its validity - expiration, chain of trust, and so on - although it may be validated by other Device Management components. For production, we recommend creating a certificate with a lifespan greater than the product's expected lifespan (for example, 20 years).</span>

* Upload the new firmware binary to a server that your devices can access, and obtain the URL for the uploaded firmware binary.

* A configuration file in JSON or YAML format (same as [`manifest-tool create`](#manifest-tool-create)).

**Example**

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

#### `manifest-tool public-key`

Create a public key file in uncompressed point format. Provisioning this file to the device enables the device to verify the manifest signature.

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

<span class="notes">**Note 1:** Additional configuration file with same name but with `.yaml` extension will be generated. Both files are required by the manifest-tool. Only the output file specified by `--output` argument should be uploaded to Pelion storage.</span>

<span class="notes">**Note 2:** Compression block size has a direct impact on the amount of memory required by the device receiving the update. The device requires twice the amount of RAM in runtime to decompress and apply the patch.</span>

<span class="notes">**Note 3:** Compression block must be aligned with network (COAP/HTTP) buffer size used for download. Misalignment in sizes may result in device failure to process the delta patch file.</span>

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

Initializes the developer environment.

* Generates credentials and a configuration file in the tool's cache directory:
    - `dev.key.pem` - An update private key.
    - `dev.cert.der` - An update public key certificate.
    - `dev.cfg.yaml` - Developer configuration file.

    The default cache directory name is `.manifest-dev-tool`.

* Generates an update resource C file with symbols that allow
  bypassing the provisioning step in the developer flow. Default name is `update_default_resources.c`.

<span class="notes">**Note 1:** Use the credentials generated by `manifest-dev-tool init` in the development stage only.</span>

<span class="notes"> **Note 2:** You can keep your access key in the `.pelion-dev-presets.yaml` file in your home directory and pass it using the `--gw-preset` option.</span>

  **Example of `.pelion-dev-presets.yaml`:**
  ```yaml
  usa:
      host: https://api.us-east-1.mbedcloud.com
      api_key: ak_SOME_VERY_SECRET_API_KEY
  japan:
      host: https://api.ap-northeast-1.mbedcloud.com
      api_key: ak_SOME_OTHER_VERY_SECRET_API_KEY
  ```

  To obtain an access key and API host URL, in Device Management Portal, click **Access Management** > **Access keys** > **New access key**. Limit access to the `.pelion-dev-presets.yaml` file to your user only.

**Example**

```shell
manifest-dev-tool init --access-key [Device Management access key]
```
Or
```shell
manifest-dev-tool init --gw-preset usa
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

<span class="notes">**Note:** To run a delta update, specifiy the [`manifest-delta-tool`](#manifest-delta-tool) output in the `--payload-path` argument and make sure the `.yaml` output with the same name sit next to that output file.</span>

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

<span class="notes">**Note:** To run a delta update, specifiy the [`manifest-delta-tool`](#manifest-delta-tool) output in the `--payload-path` argument and make sure the `.yaml` output with the same name sit next to that output file.</span>

#### `manifest-dev-tool update`

Same as [`manifest-dev-tool create`](#manifest-dev-tool-create) but also
lets you interact with Device Management Portal to run a full update
campaign.

The command:

1. Uploads the payload to Device Management Portal and obtains the URL.
1. Creates a manifest file with the URL from the previous step and
   obtains a manifest URL.
1. Creates an update campaign with the manifest URL from the previous
   step.
1. Starts the update campaign if you pass the `--start-campaign` or
   `--wait-for-completion` argument.
1. If you pass the `--wait-for-completion` argument, the tool waits for
   campaign completion for the time period specified by `--timeout` or
   until the campaign reaches one of its terminating states in Device
   Management Portal (`expired`, `userstopped`, or
   `quotaallocationfailed`).
1. If you pass the `--wait-for-completion` argument without the
   `--no-cleanup` flag, the tool removes the uploaded test resources
   from Device Management Portal before exiting.

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

### Developer workflow example for mbed-os devices

1. Clone the https://github.com/PelionIoT/mbed-cloud-client-example
   repository.
1. From within the repository, execute:

    ```
    manifest-dev-tool init -a $MY_API_KEY
    ```
    The tool initializes the developer environment and generates a `update_default_resources.c` file.
1. Build the firmware image for your device.
1. Save the `mbed-cloud-client-example_update.bin` file.
1. Flash the `mbed-cloud-client-example.bin` to the device.
1. Wait for the device to register in the cloud.
1. Make some changes to the source of the firmware application.
1. Build the firmware update candidate for your device.
    - To test delta update, create delta patch:
      ```
      manifest-delta-tool -c <original mbed-cloud-client-example_update.bin> -n <new mbed-cloud-client-example_update.bin> -o delta.bin
      ```
1. Issue an update campaign:

    ```
    manifest-dev-tool update --payload-path <new mbed-cloud-client-example_update.bin or delta.bin> --wait-for-completion
    ```

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
