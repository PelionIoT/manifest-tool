# Device Management manifest CLI tool

This document provides instructions for installing and using the manifest tool.  
Below is the table of contents:

- [Manifest tool overview](#manifest-tool-overview)
- [Installing the manifest tool](#installing-the-manifest-tool)
- [Using the manifest tool](#using-the-manifest-tool)
- [Developer workflow example](#developer-workflow-example)
- [Upgrading from manifest tool v1.5.2 and lower](#upgrading-from-manifest-tool-v152-and-lower)
- [External signing tool](#external-signing-tool)
- [Troubleshooting](#troubleshooting)

<span class="notes">**Note:** For a comprehensive list of changes between release versions, please refer to the [changelog](./changelog.md).</span>

<h2 id="manifest-tool-overview">Manifest tool overview</h2>
The Device Management allows you to carry out Firmware Over-the-Air (FOTA) updates
on managed devices.

On the device side, the firmware update process commences when the device receives an update manifest.  
The OEM (original equipment manufacturer) or the update author cryptographically signs the manifest with
a private key paired with a public key existing on the device, enabling the device to verify the 
manifest's authenticity before accepting the firmware update.

Device Management provides support for the following:

* Full updates - Deliver new firmware and install it on the device.
* Delta updates - The manifest tool executes a differential algorithm to create a small delta patch file.  
  The client uses the delta patch file and the currently installed firmware to construct a new firmware image, 
  conserving bandwidth.
* Combined updates - The FOTA client enables you to define a device component as comprising several 
  subcomponents that are always updated together and reported to the Update service as a single component.  
  For combined updates, the manifest tool generates a combined package containing multiple firmware images.  
  The client processes the combined package and installs the images in a predefined order you set on the device.

The `manifest-tool` Python package includes the following command line tools:

- [`manifest-tool`](#manifest-tool) - Used for creating manifest files.
- [`manifest-delta-tool`](#manifest-delta-tool) - Generates delta patch
  files.
- [`manifest-package-tool`](#manifest-package-tool) - Creates combined package file.
- [`manifest-dev-tool`](#manifest-dev-tool) - A developer tool for 
  simplifying update campaigns.

<h2 id="installing-the-manifest-tool">Installing the manifest tool</h2>

It is advisable to install the `manifest-tool` Python package within a segregated 
[Python virtual environment](https://virtualenv.pypa.io).

### Installing the manifest tool from [PyPi](https://pypi.org/project/manifest-tool/)

**Prerequisites:**

* [Python 3.8 ... 3.11](https://www.python.org/downloads/).
    * Python 3.12 support is not available yet.
* [pip (Python Package Installer)](https://pip.pypa.io/en/stable/).
* Internet connectivity

```
pip install manifest-tool
```

<span class="notes">**Note:** If your system runs Python 3.6 or an older version, you will need to use an earlier version
of this tool. You can install version 2.4.1 as follows:</span>

```
pip install manifest-tool==2.4.1
```

### Installing from local source tree

**Prerequisites:**

* In addition to PyPi-installation pre-requisites:
* Native toolchain:
    * GCC/Clang for Linux/MacOS.
    * [Microsoft Build Tools for Visual Studio 2019](https://www.visualstudio.com/downloads/#build-tools-for-visual-studio-2019) 
      for Windows or a different version compatible with your Python version as described [here](https://wiki.python.org/moin/WindowsCompilers).

```
$ git clone https://github.com/PelionIoT/manifest-tool.git
$ pip install <path to manifest-tool's local source tree>
```

<span class="notes">**Note:** You can use `$ pip install --editable <manifest-tool>` to install the package 
in Python setuptools development mode. For more information, please see the [setuptools development mode documentation](https://setuptools.readthedocs.io/en/latest/setuptools.html#development-mode).</span>

<h2 id="using-the-manifest-tool">Using the manifest tool</h2>

This section provides an explanation of how to use the command-line tools included in the 
`manifest-tool` Python package, which are as follows:

- [manifest-tool](#manifest-tool)
- [manifest-delta-tool](#manifest-delta-tool)
- [manifest-package-tool](#manifest-package-tool)
- [manifest-dev-tool](#manifest-dev-tool)

<h3 id="manifest-tool">manifest-tool</h3>

`manifest-tool` commands:

- [`manifest-tool create`](#manifest-tool-create) - Creates manifests.
- [`manifest-tool create-v1`](#manifest-tool-create-v1) - Creates V1
  schema-compatible manifests.
- [`manifest-tool parse`](#manifest-tool-parse) - Parses and verifies
  existing manifest files.
- [`manifest-tool schema`](#manifest-tool-schema) - Shows the bundled input
  validation schema.
- [`manifest-tool public-key`](#manifest-tool-public-key) - Generates an
  uncompressed public key.

<span class="notes">**Note:** To access more detailed information about all commands, 
you can run `manifest-tool --help`. Additionally, for specific command details, including their 
parameters and how to use them, you can run `manifest-tool <command> --help`.</span>

<h4 id="manifest-tool-create">manifest-tool create</h4>

The `manifest-tool create` command is used to generate a manifest. 
This tool takes a configuration file that defines the update type and 
creates a manifest based on the provided details.

**Prerequisites**

* An update private key and public key certificate.

    Keep the private key secure, as it enables the installation of new firmware images on your devices.

    Provision the public key to the device.

    * To generate a private key, use the following command:

        ```shell
        $ openssl ecparam -genkey -name prime256v1 -outform PEM -out my.priv.key.pem
        ```

  *   To generate a public key in uncompressed point format (X9.62), use
      the [`manifest-tool public-key`](#manifest-tool-public-key)
      command.

* Upload the new firmware image to a server that your devices can access.

* The configuration file should be in JSON or YAML format and include the following fields:
    
    ```yaml
    vendor:  # One of the "domain" or "vendor-id" fields is expected.
      domain: izumanetworks.com  # The FW owner domain, used to generate a vendor UUID.
                                 # Expected to include a dot (".").
      # OR
      vendor-id: fa6b4a53d5ad5fdfbe9de663e4d41ffe  # A valid vendor UUID.
      custom-data-path: my.custom-data.bin # Vendor's custom data file
                                           # to be passed to the target devices.
                                           # This is only relevant for manifest v3 format.

    device:  # One of the "model-name" or "class-id" fields is expected
      model-name: Smart Slippers  # A device model name, used to generate a class UUID.
      # OR
      class-id: 327c726ac6e54f7a82fbf1d3beda80f0  # A valid device-class UUID.

    priority: 1  # Update priority  to be passed to the authorization callback, 
                 # which is implemented on the device side.

    payload:
      url: http://some-url.com/files?id=1234  # Address from which the device downloads
                                              # the candidate payload.
                                              # Obtained by clicking "Copy HTTP URL" on
                                              # the Firmware image details screen
                                              # in Device Management Portal,
                                              # or by copying the `datafile` attribute.
      file-path: ./my.fw.bin  # Local path to the candidate payload file
                              # or the delta patch file.
                              # Used for digest calculation and signing.
      format: raw-binary  # One of the following:
                          #  raw-binary       - full image update campaigns.
                          #  arm-patch-stream - delta patch update campaigns.
                          # For manifest v3 only:
                          #  combined           - combined updates.
                          #  encrypted-raw      - full image update with the encrypted image.
                          #  encrypted-combined - combined updates with encrypted image.
      encrypted:  # Required for 'encrypted-raw', and 'encrypted-patch' formats.
        digest: 3725565932eb5b9fbd5767a3a534cb6a1a87813e0b4a76deacb9b36695c71307
                      # The encrypted payload digest,
                      # obtained by copying the `encrypted_datafile_checksum` attribute
                      # from the Firmware image details screen in the Device Management Portal.
        size: 471304  # The encrypted payload size,
                      # obtained by copying the `encrypted_datafile_size` attribute
                      # from the Firmware image details screen in the Device Management Portal.

    component: MAIN  # [Optional] The name of the component to be updated,
                     # relevant for manifest v3 format.
                     # By default, it is set to "MAIN" for updating
                     # the main application image.

    sign-image: True  # [Optional] A boolean field accepting True or False values,
                      # relevant for manifest v3 format.
                      # When set to True, a 64-byte raw signature over the installed
                      # image will be added to the manifest.
                      # This image signature can be used when the device bootloader
                      # expects to work with signed images (e.g. secure-boot).
                      # By default, it's set to False. 
  
    signing-tool: ./sign.sh # Path to the external signing tool.
                            # Enables signing with existing infrastructure.
                            # The tool should accept the arguments: <digest algorithm> <key identifier> <input file> <output file>.
                            # The `--key` CLI argument will be used as <key identifier>. 
    ```

**Example**

* Consider the following configuration file named `my.config.yaml`:

    ```yaml
    vendor:
      domain: izumanetworks.com
    device:
      model-name: Smart Flip-flops
    priority: 1
    payload:
      url: http://some-url.com/files?id=1234
      file-path: ./my.fw.bin
      format: raw-binary
    component: MAIN
    ```

* You can run the following command to create the manifest:

    ```shell
    manifest-tool create \
        --config my.config.yaml \
        --key my.priv.key.pem \
        --fw-version 1.2.3 \
        --output my.manifest.bin
    ```

<span class="notes">**Note:** The value of `--fw-version` refers to the firmware version of the 
component to be updated. The value can be between 0.0.1 and 999.999.999 and must be greater than 
the firmware version currently installed on the device.</span>

<h4 id="manifest-tool-create-v1">manifest-tool create-v1</h4>

The `manifest-tool create-v1` command is designed for older versions of the 
Device Management update client, which use manifest schema V1. 
These older versions assume that the public key is packaged in an x.509 certificate.

**Prerequisites**

* An update private key and public key certificate.

    Keep the private key secure as it enables the installation of new firmware images on your devices.

    Provision the public key to the device.

    * To generate a private key, use the following command:

        ```shell
        $ openssl ecparam -genkey -name prime256v1 -outform PEM -out my.priv.key.pem
        ```
    * To generate a public key x.509 certificate, run the following commands:

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

        <span class="notes">**Note:** Device Management update client treats the x.509 certificate as a 
         container **ONLY** and does not enforce its validity. such as expiration, chain of trust, etc., 
         although it may be validated by other Device Management components. 
         For production purposes, it is recommended creating a certificate with a lifespan 
         greater than the product's expected lifespan, e.g. 20 years.</span>

* Upload the new firmware binary to a server that your devices can access, and obtain the URL for the uploaded firmware binary.

* A configuration file in JSON or YAML format, as required for the [`manifest-tool create`](#manifest-tool-create) command.

**Example**

* To create a V1 schema-compatible manifest, you can run the following command:

    ```shell
    manifest-tool create-v1 \
        --config my.config.yaml \
        --key my.priv.key.pem \
        --update-certificate my.x509.certificate.der \
        --output my.manifest.bin
    ```

<h4 id="manifest-tool-parse">manifest-tool parse</h4>

The `manifest-tool parse` command is used to parse and validate existing manifest files.

**Prerequisites**

* A manifest file (for example `my.manifest.bin`).
* Optionally, you can provide an update private key, public key, or certificate to
  validate the manifest's signature.

**Example**

You can run the following command to parse and validate a manifest file:

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

<h4 id="manifest-tool-schema">manifest-tool schema</h4>

The `manifest-tool schema` command is used to print the input validation JSON schema 
that is bundled with the current tool. 
This schema can serve as a self-documenting reference to help you better understand and validate 
the manifest tool's input configuration.

**Example**

You can execute the following command to print the input validation schema:

```shell
$ manifest-tool schema
```

<h4 id="manifest-tool-public-key">manifest-tool public-key</h4>

The `manifest-tool public-key` command is used to create a public key file in uncompressed point format. 
Provisioning this file to the device enables the device to verify the manifest's signature.

**Example**

To create a public key file from a private key (for example, `my.priv.key.pem`) and 
save it as `my.pub.key.bin`, you can use the following command:

```shell
manifest-tool public-key my.priv.key.pem --out my.pub.key.bin
```

<h3 id="manifest-delta-tool">manifest-delta-tool</h3>

The `manifest-delta-tool` is used to generate delta patch files, which are required for delta updates.

Run `manifest-delta-tool --help` for more information about usage and
arguments.

**Prerequisites**

* The firmware currently installed on the device and the updated
  firmware image. These are required for calculating the delta patch.

**Example**

You can use the following command to generate a delta patch file:

```shell
$ manifest-delta-tool -c current_fw.bin -n new_fw.bin -o delta-patch.bin
```

**Notes:**
1. An additional configuration file with the same name but with the `.yaml` 
extension will be generated. Both files are required by the manifest tool. 
Only the output file specified by the `--output` argument should be uploaded to the Izuma cloud.

1. The compression block size has a direct impact on the amount of 
memory required by the device receiving the update. The device requires twice the amount of RAM 
during runtime to decompress and apply the patch.

1. The compression block must be aligned with the network (COAP/HTTP) 
buffer size used for download. Misalignment in sizes may result in device's failure to process the 
delta patch file.

<h3 id="manifest-package-tool">manifest-package-tool</h3>

Use this tool to generate combined package files for combined updates.

`manifest-package-tool` commands:

- [`manifest-package-tool create`](#manifest-package-tool-create) - Creates a combined package file for combined updates.
- [`manifest-package-tool parse`](#manifest-package-tool-parse) - Parses and verifies existing combined package files.

<span class="notes">**Note:** Run `manifest-package-tool --help` for more information about all commands, or `manifest-package-tool <command> --help` for more information about a specific command, including its parameters and how to use them.</span>

<h4 id="manifest-package-tool-create">manifest-package-tool create</h4>

The `manifest-package-tool create` command is used to create a combined package file 
based on a configuration file that contains information about firmware images for a combined update.

**Prerequisites**

* The configuration file should be in JSON or YAML format and include the following fields:
    
    ```yaml
    images:                        # Two or more images
    - file_name:  ./my.fw1.bin     # Local path to one of the firmware images.
      sub_comp_name:  fw1_id       # Name of the subcomponent firmware image.
      vendor_data: fw1_vend        # Vendor data for the firmware image.
    - file_name:  ./my.fw2.bin     # Local path to another firmware image.
      sub_comp_name:  fw2_id       # Name of the subcomponent firmware image.
      vendor_data: fw2_vend        # Vendor data for the firmware image.
    ```

* New firmware images to be included in the combined package. 
  In this example `./my/fw1.bin` and `./my.fw2.bin`.


**Example**

You can create a combined package by using the following command:

```shell
$ manifest-package-tool create --config combined_package_config.yaml --output combined_package_file
```

In this example, `combined_package_config.yaml` is the input configuration file.

The tool creates a tar-format combined package with the firmware images listed in the configuration file, where:

- `file_name` is the local path to the image file.
- `sub_comp_name` is the name the tool gives to the subcomponent firmware image file in the combined package. 
   This name must match the name (`sub_comp_name`) defined on the device.
- `vendor_data` is the vendor information of the firmware image.

In addition to the firmware image files, the tool creates a descriptor `__desc__` file 
inside the `tar` package, which provides information about the contents of the combined package to 
the FOTA update client.

**Notes:**
1. The FOTA update client reports on a combined update as an update of a 
single component (defined as `comp_name` on the device), consisting of multiple subcomponents 
(each defined as `sub_comp_name` on the device). When creating a combined package, each `sub_comp_name` 
must correspond to a `sub_comp_name` on the device. 
For more information, see [Implementing combined update](https://developer.izumanetworks.com/docs/device-management/current/connecting/implementing-combined-update.html)

2. When creating a manifest for a combined update using `manifest-tool`, in the manifest configuration 
file, set the `format` field to `combined` or `encrypted-combined`, set the `component` field to the 
name of the component you are updating, and set the `file-path` field to the path of the combined 
package file.

3. To use a combined package file with the `manifest-dev-tool create` or `update` commands, 
set the path of the combined package file in the `-p` argument and pass the `--combined-image` flag 
to indicate that the current candidate payload is a combined image.

<h4 id="manifest-package-tool-parse">manifest-package-tool parse</h4>

The `manifest-package-tool parse` command is used to parse and validate existing combined package files.

**Prerequisites**

* A combined package file (for example `combined_package_file`).

**Example**

You can run the following command to parse and validate a combined package file:

```shell
$ manifest-package-tool parse --package combined_package_file
Contents of the tar package -
File name : _desc_
File name : fw1_id
File name : fw1_id
Information of update images:
OrderedDict([('id', b'fw1_id'), ('vendor-data', b'fw1_vend'), ('vendor-data-size', 8), ('image-size', 417053)])
OrderedDict([('id', b'fw2_id'), ('vendor-data', b'fw2_vend'), ('vendor-data-size', 8), ('image-size', 253482)])
```

<h3 id="manifest-dev-tool">manifest-dev-tool</h3>

The `manifest-dev-tool` is a developer tool designed for running a simplified update campaign. 
It is primarily intended for use in development flows and testing. 

`manifest-dev-tool` commands:
- [`manifest-dev-tool init`](#manifest-dev-tool-init) - Initializes the
  developer environment.
- [`manifest-dev-tool create`](#manifest-dev-tool-create) - A simplified
  tool for creating manifests.
- [`manifest-dev-tool create-v1`](#manifest-dev-tool-create-v1) -
  A simplified tool for creating manifests using the V1 schema.
- [`manifest-dev-tool update`](#manifest-dev-tool-update) - Allows you to
  perform end-to-end tests without leaving the command shell.
- [`manifest-dev-tool update-v1`](#manifest-dev-tool-update-v1) - Allows
  you to perform end-to-end tests without leaving the command shell using a
  V1-schema manifest.


<span class="notes">**Note:** You can run `manifest-dev-tool --help` for more information about 
all commands, or `manifest-dev-tool <command> --help` for more detailed information about a 
specific command, including its parameters and how to use them.</span>

<h4 id="manifest-dev-tool-init">manifest-dev-tool init</h4>

The `manifest-dev-tool init` command is used to initialize the developer environment. 

* Generates credentials and a configuration file in the tool's cache directory:
    - `dev.key.pem` - An update private key.
    - `dev.cert.der` - An update public key certificate.
    - `dev.cfg.yaml` - Developer configuration file.

    The default cache directory name is `.manifest-dev-tool`.

* Generates an update resource C file with symbols that allow
  bypassing the provisioning step in the developer flow. 
  The default name is `update_default_resources.c`.

**Notes**
1. Use the credentials generated by `manifest-dev-tool init` in the development stage only.
2. You can keep your access key in the `.izuma-dev-presets.yaml` file in your home directory 
and pass it using the `--gw-preset` option.

  **Example of `.izuma-dev-presets.yaml`:**
  ```yaml
  usa:
      host: https://api.us-east-1.mbedcloud.com
      access_key: ak_SOME_VERY_SECRET_ACCESS_KEY
  japan:
      host: https://api.ap-northeast-1.mbedcloud.com
      access_key: ak_SOME_OTHER_VERY_SECRET_ACCESS_KEY
  ```

  To obtain an access key and API host URL, in the Device Management Portal, 
  click **Access Management** > **Access keys** > **New access key**. 
  Limit access to the `.izuma-dev-presets.yaml` file to your user only.

**Example**

You can run `manifest-dev-tool init` with an access key as follows:

```shell
manifest-dev-tool init --access-key [Device Management access key]
```
Or
```shell
manifest-dev-tool init --gw-preset usa
```

<h4 id="manifest-dev-tool-create">manifest-dev-tool create</h4>

The `manifest-dev-tool create` command is used to create developer manifest files 
without requiring an input configuration file.

**Example**

You can create a developer manifest with the following command:

```shell
manifest-dev-tool create \
    --payload-url http://test.pdmc.izumanetworks.com?fileId=1256 \
    --payload-path new_fw.bin \
    --fw-version 1.2.3 \
    --component-name MAIN \
    --output update-manifest.bin
```

**Notes**:
1. To run a delta update, specify the output of [`manifest-delta-tool`](#manifest-delta-tool) 
in the `--payload-path` argument and ensure that the `.yaml` output with the same name sits 
next to that output file.
2. You can add the `--sign-image` argument to update a device with a secure bootloader 
that requires an image signature.

<h4 id="manifest-dev-tool-create-v1">manifest-dev-tool create-v1</h4>

The `manifest-dev-tool create-v1` command is used to create developer manifest files in v1 
format without requiring an input configuration file.

**Example**

You can create a developer manifest in v1 format with the following command:

```shell
manifest-dev-tool create-v1 \
    --payload-url http://test.pdmc.izumanetworks.com?fileId=1256 \
    --payload-path new-fw.bin \
    --output update-manifest.bin
```

<span class="notes">**Note:** To run a delta update, specify the output of [`manifest-delta-tool`](#manifest-delta-tool) 
in the `--payload-path` argument and ensure that the `.yaml` output with the same name sits next to that output file.</span>

<h4 id="manifest-dev-tool-update">manifest-dev-tool update</h4>

The `manifest-dev-tool update` command is similar to `manifest-dev-tool create`, 
but it also allows you to interact with Device Management to run a full update campaign. 
The command performs the following actions:

1. Uploads the payload to Device Management and obtains the URL.
1. Create a manifest file with the URL from the previous step and
   obtains a manifest URL.
1. Creates an update campaign with the manifest URL from the previous
   step.
1. Starts the update campaign if you pass the `--start-campaign` or
   `--wait-for-completion` argument.
1. If you pass the `--wait-for-completion` argument, the tool waits for
   the campaign to complete for the time period specified by `--timeout` or
   until the campaign reaches one of its terminating states.
1. If you pass the `--wait-for-completion` argument without the
   `--no-cleanup` flag, the tool removes the uploaded test resources
   from Device Management before exiting.

**Example**

You can run a full update campaign with the following command:

  ```shell
  manifest-dev-tool update \
      --payload-path my_new_fw.bin \
      --fw-version 1.2.3 \
      --wait-for-completion
  ```

<span class="notes">**Note:** The tool creates the device filter for the campaign based on the 
unique `class-id` and `vendor-id` fields generated by the 
[`manifest-dev-tool init`](#manifest-dev-tool-init) command.</span>

<h4 id="manifest-dev-tool-update-v1">manifest-dev-tool update-v1</h4>

The `manifest-dev-tool update-v1` command is similar to `manifest-dev-tool update`, 
but it works with a v1-format manifest.

**Example**

You can run a full update campaign with a v1-format manifest using the following command:

  ```shell
  manifest-dev-tool update-v1 \
      --payload-path my_new_fw.bin \
      --wait-for-completion
  ```

<h2 id="developer-workflow-example">Developer workflow example for Mbed OS devices</h2>

1. Clone the https://github.com/PelionIoT/mbed-cloud-client-example
   repository.
1. From within the repository, execute the following command to initialize the developer environment 
and generate an `update_default_resources.c` file:

    ```shell
    manifest-dev-tool init -a $MY_ACCESS_KEY
    ```    
1. Build the firmware image for your device.
1. Save the `mbed-cloud-client-example_update.bin` file.
1. Flash the `mbed-cloud-client-example.bin` to the device.
1. Wait for the device to register in the cloud.
1. Make some changes to the source of the firmware application.
1. Build the firmware update candidate for your device.
    - To test the delta update, create a delta patch:
      ```shell
      manifest-delta-tool -c <original mbed-cloud-client-example_update.bin> -n <new mbed-cloud-client-example_update.bin> -o delta.bin
      ```
1. Issue an update campaign with the following command::

    ```shell
    manifest-dev-tool update --payload-path <new mbed-cloud-client-example_update.bin or delta.bin> --wait-for-completion
    ```

<h2 id="upgrading-from-manifest-tool-v152-and-lower">Upgrading from manifest tool v1.5.2 and lower</h2>

Manifest tool v2.0.0 is not compatible with previous versions.

This section explains how to migrate your existing configuration and credentials 
for use with manifest-tool version 2.2.0 and higher.

* Initializing the development environment using previously-defined configuration and credentials.

    Run the following [`manifest-dev-tool init`](#manifest-dev-tool-init) command:

    ```shell
    manifest-dev-tool init --api-url <API URL> \
                           --access-key <Access key> \
                           --vendor-id <Vendor ID> \
                           --class-id <Class ID> \
                           --key <private key path> \
                           --update-certificate <certificate path>
    ```
    Where `<API URL>` and `<Access key>` are the values from the previous `.mbed_cloud_config.json` file,
    `<Vendor ID>` and `<Class ID>` are the values from the previous `.manifest_tool.json` file, 
    and `<private key path>` and `<certificate path>` are the paths to your private key and 
    update certificate, respectively.

    Once the command finishes successfully, you can remove the previously created files.

* Adapting the create manifest configuration

    If you use `manifest-tool` (not `manifest-dev-tool`), create a new configuration file, 
    as described in [manifest-tool create](#manifest-tool-create), and copy the relevant information 
    from your existing `.manifest_tool.json` file. This ensures that your existing configuration and 
    credentials are adapted for use with the new version of manifest-tool.

<h2 id="external-signing-tool">External signing tool</h2>

Typically, the manifest tool is responsible for digitally signing the manifest binary.  
However, in a production environment where a hardware security module (HSM) is utilized for signing operations, it is preferable to have the HSM perform the manifest signing instead.   
The manifest tool can seamlessly integrate with an external signing tool for this purpose.  

The external signing tool should be configured to accept the following parameters:

```shell
<digest algorithm> <key identifier> <input file> <output file>
```

Only SHA256 is currently supported as <digest algorithm>.
Before invoking the script, the manifest tool populates the `<input file>` with the data to be signed.  
Once the script execution is completed, the manifest tool retrieves the signature from the `<output file>`.  
It's important to note that both of these files should be in their raw binary form.

Here is an explanation of how to utilize an external signing tool in both developer and production modes.

**Production mode**

To generate a manifest signed by an external signing tool, follow these steps:

1. Include the following key in the configuration JSON or YAML file used 
   as a parameter for the `manifest-tool create` command:
   ```
   signing-tool: ./sign.sh # Path to the external signing tool.
                           # Enables signing with existing infrastructure.
                           # The tool should accept the arguments: <digest algorithm> <key identifier> <input file> <output file>.
                           # The `--key` CLI argument will be used as <key identifier>.
   ```
2. Execute the `manifest-tool create` command with the `$SIGNING_KEY_ID`
   argument. This will use the specified `$SIGNING_KEY_ID` with the `signing-tool` script.
   ```shell
    manifest-tool create \
         --config config.yaml \
         --key $SIGNING_KEY_ID \
         --fw-version 1.2.3 \
         --output my.manifest.bin 
    ```
  
These steps enable the creation of a manifest signed by the designated 
external signing tool in a production environment.

**Developer mode**

To test the external signing tool feature, it can be beneficial to use the developer flow.  
Start by executing the [`manifest-dev-tool init`](#manifest-dev-tool-init) command with the `-s`, `--key` and `--update-certificates` parameters as follows:
The `$UPDATE_CERTIFICATE` certificate should match the `$KEY`

```shell
manifest-dev-tool init \
     -a $MY_ACCESS_KEY \
     -s $SIGNING_TOOL  \
     --key $KEY        \
     --update-certificate $UPDATE_CERTIFICATE
```

After the initiation of the `manifest-dev-tool`, the subsequent `manifest-dev-tool` commands such as [`update`](#manifest-dev-tool-update), [`update-v1`](#manifest-dev-tool-update-v1), [`create`](#manifest-dev-tool-create), and [`create-v1`](#manifest-dev-tool-create-v1) will employ the external `SIGNING_TOOL` script to sign the manifest using the specified `SIGNING_KEY_ID`.

<h2 id="troubleshooting">Troubleshooting</h2>

When encountering unexpected errors with the manifest tool, it can be helpful to get more 
context on the failure. Here are some common issues and their solutions:

* **Getting more context on unexpected errors.**  

   When the tool exits with a non-zero return code, it may be helpful to
   get more context on the failure.

   **Solution:** Execute the tool with the `--debug` flag at the top
   argument parser level. For example:

   ```
   manifest-dev-tool --debug update
   ```

* **`manifest-dev-tool update ... --wait-for-completion` takes longer than expected.**

   `manifest-dev-tool update` creates a unique `class-id` and
   `vendor-id` generated per developer. Device Management expects a
   single device with these properties to connect to Device Management.

   During development, a device's `device-id` might change 
   after wiping out its storage, leading to two different devices with 
   the same `class-id` and `vendor-id`. In this scenario, 
   Device Management will try to update both devices, 
   although one of them no longer exists.

   **Solution:** Manually delete the unwanted device from Device
   Management. Alternatively, run `manifest-dev-tool update ...
   --wait-for-completion` with `--device-id DEVICE_ID` to override the
   default campaign filter and target a specific device by its ID.

* **Update fails and `manifest-dev-tool update ...
  --wait-for-completion` cleans all resources.**

   You might want to leave the resources (firmware image candidate,
   update manifest, and update campaign) on a service for further
   investigation or retry.

    **Solution:** Execute `manifest-dev-tool update ...
    --wait-for-completion` with the `--no-cleanup` flag.

* **Device does not support this manifest schema**

   **Solution:** Your device does not support the created manifest schema. 
   Switch from the `create` or` update` command to the `create-v1` or` update-v1` command respectively
   and vice versa. Make sure the manifest schema aligns with your device's compatibility.
