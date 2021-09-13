# Changelog

## 2.4.0
- Add `manifest-package-tool`:
  - New tool to generate combined package files for combined updates.
- Update the `README.md` file.

## 2.3.0
- Add encrypted payload support to `manifest-tool`:
  - Add `encrypted-raw` payload format and encrypted payload information to manifest configuration file.
- Add encrypted payload support to `manifest-dev-tool`:
  - Add `--encrypted-digest` and `--encrypted-size` options to `create` command.
  - Add `--encrypt-payload` option to `update`.
- Build wheels for `manylinux_2_24_x86_64`.
- Improve the tool help and the `README.md` file.

## 2.2.0
- Changes to `manifest-dev-tool`:
  - Improve timeout and connection error handling.
  - Add skipped and failed reasons to campaign summary.
  - Add `--key` and `--update-certificate` options to `init` command to initialize the development environment with existing credentials.
- Add `--fw-migrate-ver` option to v1 commands. This lets you set a semantic version for the firmware when upgrading from Device Management Client 4.7.1 and lower to Device Management Client 4.8.0 and higher, which supports manifest schema v3.
- Improve manifest configuration file validation.
- Use `access_key` in configuration files but continue to accept `api_key` for backward compatibility.
- Set minimum SemVer value to `0.0.1`.
- Improve the tool help and the `README.md` file.
- Update license and copyrights information.

## 2.1.1
- Remove support for Python 3.5.
- In v1 schema, allow creating manifests without the `priority` field.
- Changes to the `manifest-dev-tool`:
  - Fix usage of https://api.us-east-1.mbedcloud.com as default Pelion Device Management API URL.
- Changes to the `manifest-dev-tool update` command:
  - Add `--use-short-url` option. Using this option decreases manifest size.
    **Note:** The device must be configured to use CoAP.
  - Add `--gw-preset` option, which enables presetting an access key in a `.pelion-dev-presets.yaml` file in the home directory.
  - Print campaign summary on tool exit.
  - Upload firmware images smaller than 100MB with the `/v3/firmware-images` API.
- Improve the tool help and the `README.md`.

## 2.1.0
- Stop using deprecated `mbed-cloud-sdk` package
- Introduce support for `upload-jobs` for uploading FW image - allow
  uploading files bigger than 100MB
- Assert campaign is started when calling `manifest-dev-tool update
  --wait-for-completion`
- Assert all devices targeted by the update campaign were successfully
  updated when calling `manifest-dev-tool update --wait-for-completion`
- Add an option to specify custom vendor and class IDs to 
  `manifest-dev-tool init` command. Check the `--help` for details
- Fixed `manifest-tool parse` output formatting - improves readability
- Deprecate `-f/--force` flags in `manifest-dev-tool init`. The default 
  behavior will always reinitialize the environment. The flag is still 
  supported but has no effect and deprecation warning message will be 
  emitted.

## 2.0.0
Works with client-lite.

Key differences from previous version:

|                                   | Manifest-tool <= 1.4.8     | Manifest-tool>=1.5.0       | Manifest >= 2.0.0                                                           |
|:----------------------------------|:---------------------------|:---------------------------|:----------------------------------------------------------------------------|
| Supported manifest schema version | `v1`                       | `v1`                       | `v1` and `v3`                                                               |
| Delta update                      | Not Supported              | Supported                  | Supported                                                                   |
| Component update                  | Not supported              | Not supported              | Supported                                                                   |
| PDMC                              | Supported 3.4.0 or earlier | Supported 3.4.0 or later   | `v1` support covers PDMC, `v3` support is only available on Client Lite     |
| Client Lite                       | Supported                  | Supported                  | Supports both `v1` (by default) and `v3` and can be configured at build time|

**Changes:**

- introduce new ASN manifest format `v3`
- added delta-tool as Python module
- introduced [Semantic version](https://semver.org/) format
- add an option to sign candidate image using update private key -
  allowing to implement secure boot on a device side
- work with ECDSA raw signatures `(R||S)` - reduce verify code size on
  target device
- simplified command line interface
  - split between developer and production tools:
    - `manifest-tool` - is for production use
    - `manifest-dev-tool` - is for developer use only
    - `manifest-delta-tool` - is the tool for preparing delta patches
- cleanup developer tool CLI by removing various configuration that
  have no practical use at current point
- backward comparability with ASN manifest format v1 is preserved via
  dedicated commands:
   - `manifest-tool create-v1`
   - `manifest-dev-tool update-v1`
   - `manifest-dev-tool create-v1`

# 1.5.2
