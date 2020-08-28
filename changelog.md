# Changelog

## 2.1.0
- Stop using deprecated `mbed-cloud-sdk` package
- Introduce support for `upload-jobs` for uploading FW image - allow
  uploading files bigger than 100MB
- Assert campaign is started when calling `manifest-dev-tool update
  --wait-for-completion`
- Assert all devices targeted by the update campaign were successfully
  updated when calling `manifest-dev-tool update --wait-for-completion`

## 2.0.0
Works with client-lite.

Key differences from previous version:

|                                   | Manifest 1.5.2             | Manifest 2.0.0                                                              |
|:----------------------------------|:---------------------------|:----------------------------------------------------------------------------|
| Supported manifest schema version | `v1`                       | `v1` and `v3`                                                               |
| Delta update                      | Supported                  | Supported                                                                   |
| Component update                  | Not supported              | Supported                                                                   |
| PDMC                              | Supported 4.5.0 or earlier | `v1` support covers PDMC, `v3` support is only available on Client Lite     |
| Client Lite                       | Supported                  | Supports both `v1` (by default) and `v3` and can be configured at build time|

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
