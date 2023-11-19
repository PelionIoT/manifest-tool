# ----------------------------------------------------------------------------
# Copyright 2019-2021 Pelion
# Copyright 2022-2023 Izuma Networks
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
"""Manifest-dev-tool init command."""
import argparse
import datetime
import logging
import time
import uuid
from pathlib import Path
import shutil
from typing import Optional

import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from manifesttool import __version__
from manifesttool.dev_tool import defaults
from manifesttool.mtool import ecdsa_helper

SCRIPT_DIR = Path(__file__).resolve().parent

logger = logging.getLogger("manifest-dev-tool-init")


def uuid_factory(value: str) -> uuid.UUID:
    """
    Construct UUID from a string command line argument.

    :param value: input string
    :return: UUID
    """
    try:
        return uuid.UUID(hex=value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            '"{}" is a malformed hexadecimal UUID string'.format(value)
        ) from exc


def register_parser(parser: argparse.ArgumentParser):
    """Register the parser."""
    optional = parser.add_argument_group("optional arguments")

    optional.add_argument(
        "-h", "--help", action="help", help="Show this help message and exit."
    )

    optional.add_argument(
        "--cache-dir",
        help="Tool's cache directory for preserving the state between "
        '"init", "create" and "update" command invocations. '
        "[Default: {}]".format(defaults.BASE_PATH),
        type=Path,
        default=defaults.BASE_PATH,
    )

    optional.add_argument(
        "-g",
        "--generated-resource",
        help="Generated update resource C filename. "
        "[Default: {}]".format(defaults.UPDATE_RESOURCE_C),
        type=Path,
        default=defaults.UPDATE_RESOURCE_C,
    )

    optional.add_argument(
        "--vendor-id",
        help="Set custom vendor UUID. [Default: random UUID]",
        type=uuid_factory,
        default=uuid.uuid4(),
    )

    optional.add_argument(
        "--class-id",
        help="Set custom class UUID. [Default: random UUID]",
        type=uuid_factory,
        default=uuid.uuid4(),
    )

    optional.add_argument(
        "--update-certificate",
        help="""
        Path to the update certificate file.
        The parameter must come together with `--update-certificate` argument
        """,
        type=Path,
    )

    optional.add_argument(
        "--key",
        help="""
        A private key file that sings the manifest.
        Could be a path to the PEM format private key file.
        It could also be an identifier for a private key,
        if `signing-tool` parameter is supplied.
        The `--key` parameter must come together with
        `--update-certificate` argument.
        """,
        type=Path,
    )

    optional.add_argument(
        "-s",
        "--signing-tool",
        help="""
             An external tool that signs the manifest.
             This allows signing with existing infrastructure.
             The arguments to the tool are:
             <digest algorithm> <key identifier> <input file> <output file>.
             Only SHA256 is currently supported as <digest algorithm>.
             The parameter must come together with `--key`
             and `--update-certificate` arguments.
             The `--key` will be used as <key identifier>
             """,
        type=Path,
    )

    service = parser.add_argument_group(
        "optional arguments (Izuma Device Management service configuration)"
    )

    service.add_argument(
        "-p",
        "--gw-preset",
        help="The preset name defined in {}, "
        " which specifies a URL and "
        "access key.".format(defaults.IZUMA_GW_PATH),
        choices=defaults.IZUMA_GW.keys() if defaults.IZUMA_GW else [],
    )
    service.add_argument(
        "-a",
        "--access-key",
        "--api-key",
        help="Access key for accessing a Izuma Device Management API.",
    )
    service.add_argument(
        "-u",
        "--api-url",
        help="Izuma Device Management API URL. "
        "[Default: {}]".format(defaults.API_GW),
        default=defaults.API_GW,
    )


def chunks(arr, num_of_elements):
    """Split the array into chunks of number of elements."""
    for i in range(0, len(arr), num_of_elements):
        yield arr[i : i + num_of_elements]


def format_rows(arr):
    """Format the chunks as hexadecimal values in a string."""
    for _slice in chunks(arr, 8):
        yield ", ".join(["0x{:02X}".format(x) for x in _slice])


def pretty_print(arr):
    """Create list from the format rows."""
    return ",\n    ".join(list(format_rows(arr)))


def generate_update_default_resources_c(
    c_source: Path,
    vendor_id: uuid.UUID,
    class_id: uuid.UUID,
    cert_file: Path,
):
    """
    Generate update resources C source file for developer convenience.

    :param c_source: generated C source file
    :param vendor_id: vendor UUID
    :param class_id: class UUID
    :param cert_file: update certificate file
    """
    vendor_id_str = pretty_print(vendor_id.bytes)
    class_id_str = pretty_print(class_id.bytes)

    cert_data = cert_file.read_bytes()

    cert_str = pretty_print(cert_data)

    template = (SCRIPT_DIR / "code_template.txt").read_text()

    public_key = ecdsa_helper.public_key_from_certificate(cert_data)
    public_key_bytes = ecdsa_helper.public_key_to_bytes(public_key)
    update_public_key_str = pretty_print(public_key_bytes)

    c_source.write_text(
        template.format(
            vendor_id=vendor_id_str,
            class_id=class_id_str,
            cert=cert_str,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S %Z"),
            tool="manifest-dev-tool init",
            version=__version__,
            update_pub_key=update_public_key_str,
        )
    )
    logger.info("generated update source %s", c_source)


def import_credentials(
    origin_cert_file: Path,
    dest_cert_file: Path,
    origin_key_file: Optional[Path],
    dest_key_file: Optional[Path],
):
    """
    Import developer credentials.

    :param origin_cert_file - path to .der public key certificate file
    :param dest_cert_file - destination file path
    :param origin_key_file - If provided, path to .pem signing key file
    :param dest_key_file - If provided, destination file path

    """
    logger.info("importing dev-credentials")

    if origin_key_file is not None:
        if origin_key_file != dest_key_file:
            shutil.copy(origin_key_file, dest_key_file)
            logger.info("imported %s to %s", origin_key_file, dest_key_file)

    if origin_cert_file != dest_cert_file:
        shutil.copy(origin_cert_file, dest_cert_file)
        logger.info("imported %s to %s", origin_cert_file, dest_cert_file)

    logger.info("dev-credentials - imported")


def generate_credentials(
    key_file: Path, cert_file: Path, cred_valid_time: int
):
    """
    Generate developer credentials.

    :param key_file - path to .pem signing key file
    :param cert_file - path to .der public key certificate file
    :param cred_valid_time - x.509 certificate validity period
    """
    try:
        logger.info("generating dev-credentials")
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # For a self-signed certificate the
        # subject and issuer are always the same.
        subject_list = [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "localhost")
        ]

        subject = issuer = x509.Name(subject_list)

        subject_key = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        hash_ctx = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_ctx.update(subject_key)
        key_digest = hash_ctx.finalize()

        subject_key_identifier = key_digest[
            : 160 // 8
        ]  # Use RFC7093, Method 1

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow()
                + datetime.timedelta(days=cred_valid_time)
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier(subject_key_identifier),
                critical=False,
                # Sign our certificate with our private key
            )
            .sign(key, hashes.SHA256(), default_backend())
        )

        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        logger.info("created %s", key_file)

        cert_file.parent.mkdir(parents=True, exist_ok=True)
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.DER))

        logger.info("created %s", cert_file)

        logger.info("dev-credentials - generated")

    except ValueError:
        logger.error("failed to generate dev-credentials")

        if key_file.is_file():
            key_file.unlink()
        if cert_file.is_file():
            cert_file.unlink()
        raise


def generate_developer_config(
    key,
    cert_file: Path,
    config: Path,
    vendor_id: uuid.UUID,
    class_id: uuid.UUID,
    signing_tool: Optional[Path] = None,
):
    """
    Generate developer config.

    :param key - can be a path to .pem signing key file or
    a key identifier in case `signing_tool` is configured
    :param cert_file - path to .der public key certificate file
    :param config - config file
    :param vendor_id - vendor ID
    :param class_id - class ID
    :param signing_tool - optional parameter, external signing tool
    """
    cfg_data = {
        "key_file": str(key),
        "certificate": cert_file.as_posix(),
        "class-id": class_id.bytes.hex(),
        "vendor-id": vendor_id.bytes.hex(),
    }

    if signing_tool is not None:
        cfg_data["signing-tool"] = signing_tool.as_posix()

    config.parent.mkdir(parents=True, exist_ok=True)
    with config.open("wt") as fh:
        yaml.dump(cfg_data, fh)

    logger.info("generated developer config file %s", config)
    logger.debug("input_cfg=\n%s", yaml.dump(cfg_data))


def generate_service_config(
    access_key: str, api_url: str, api_config_path: Path
):
    """
    Generate service config.

    :param access_key - access key to the Izuma service
    :param api_url - API URL of the Izuma service
    :param api_config_path - path to a config file
    """
    cfg = {}

    if access_key is None or api_url is None:
        return

    if api_config_path.is_file():
        with api_config_path.open("rt") as fh:
            cfg = yaml.safe_load(fh)
            # if generated with previous versions
            # delete api_key
            if "api_key" in cfg:
                cfg.pop("api_key")

    cfg["access_key"] = access_key
    cfg["host"] = api_url

    with api_config_path.open("wt") as fh:
        yaml.safe_dump(cfg, fh)

    logger.info("generated service config file %s", api_config_path)


def entry_point(args, parser: argparse.ArgumentParser):
    """Entry point."""
    cache_dir = args.cache_dir
    cache_dir.mkdir(parents=True, exist_ok=True)

    vendor_id = args.vendor_id
    class_id = args.class_id

    signing_tool = getattr(args, "signing_tool", None)
    key = getattr(args, "key", None)
    update_certificate = getattr(args, "update_certificate", None)

    if signing_tool and (not key or not update_certificate):
        parser.error(
            "--signing-tool requires also --key and --update-certificate."
        )

    if key or update_certificate:
        if not update_certificate or not key:
            parser.error(
                "require both --key and --update-certificate or none of those."
            )

        import_cert = update_certificate
        import_key = None
        dest_key_file = None
        if not signing_tool:
            # If signing tool isn't supplied the given key should be imported
            import_key = key
            dest_key_file = cache_dir / defaults.UPDATE_PRIVATE_KEY

        import_credentials(
            origin_cert_file=import_cert,
            dest_cert_file=cache_dir / defaults.UPDATE_PUBLIC_KEY_CERT,
            origin_key_file=import_key,
            dest_key_file=dest_key_file,
        )
    else:
        # If a key and a certificate aren't given, they will be generated
        key = cache_dir / defaults.UPDATE_PRIVATE_KEY
        generate_credentials(
            key_file=key,
            cert_file=cache_dir / defaults.UPDATE_PUBLIC_KEY_CERT,
            cred_valid_time=365 * 20,  # years
        )

    generate_developer_config(
        key=key,
        cert_file=cache_dir / defaults.UPDATE_PUBLIC_KEY_CERT,
        config=cache_dir / defaults.DEV_CFG,
        vendor_id=vendor_id,
        class_id=class_id,
        signing_tool=signing_tool,
    )

    generate_update_default_resources_c(
        c_source=args.generated_resource,
        vendor_id=vendor_id,
        class_id=class_id,
        cert_file=cache_dir / defaults.UPDATE_PUBLIC_KEY_CERT,
    )
    access_key = args.access_key
    if not access_key and hasattr(args, "gw_preset") and args.gw_preset:
        access_key = defaults.IZUMA_GW[args.gw_preset].get("access_key")
        if not access_key:
            access_key = defaults.IZUMA_GW[args.gw_preset].get("api_key")

    api_url = args.api_url
    if hasattr(args, "gw_preset") and args.gw_preset:
        api_url = defaults.IZUMA_GW[args.gw_preset].get("host")

    generate_service_config(
        access_key=access_key,
        api_url=api_url,
        api_config_path=cache_dir / defaults.CLOUD_CFG,
    )

    if not access_key:
        logger.warning(
            "Access key not provided, so assisted "
            "campaign management will not be available"
        )

    (cache_dir / defaults.DEV_README).write_text(
        'Files in this directory are autogenerated by "manifest-dev-tool init"'
        " tool for internal use only.\nDo not modify.\n"
    )
