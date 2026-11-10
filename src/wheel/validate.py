"""
Strict cross-checking of wheel metadata for pre-distribution validation.

This module offers an opt-in, read-only consistency check that backends can
run before accepting a wheel for distribution. Unlike the lenient reading
interface in :mod:`wheel.wheelfile`, it refuses ambiguous archives instead of
picking the first matching piece of metadata, and it cross-checks the project
name, version and compatibility tags between the wheel filename, the
``.dist-info`` directory, ``METADATA`` and ``WHEEL``.

The check never imports the packaged code and never infers platform
capabilities from file extensions found inside the archive.
"""

from __future__ import annotations

__all__ = ["WheelValidationError", "validate_wheel"]

import email.policy
import os.path
from email.message import Message
from email.parser import BytesParser
from typing import TYPE_CHECKING
from zipfile import BadZipFile, ZipFile

from packaging.tags import InvalidTag
from packaging.utils import (
    InvalidWheelFilename,
    canonicalize_name,
    parse_tag,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from .wheelfile import WheelError

if TYPE_CHECKING:
    from _typeshed import StrPath


class WheelValidationError(WheelError):
    """Raised when a wheel fails strict metadata consistency validation."""


def _dist_info_members(names: list[str]) -> dict[str, list[str]]:
    """Map top-level .dist-info directory names to their member files."""
    dist_infos: dict[str, list[str]] = {}
    for name in names:
        dir_name, sep, file_name = name.partition("/")
        if (
            sep
            and dir_name.endswith(".dist-info")
            and file_name
            and "/" not in file_name
        ):
            dist_infos.setdefault(dir_name, []).append(file_name)
    return dist_infos


def _split_dist_info(dir_name: str) -> tuple[str, str]:
    name_ver = dir_name[: -len(".dist-info")]
    name, sep, version = name_ver.rpartition("-")
    if not sep:
        raise WheelValidationError(
            f"Malformed .dist-info directory name {dir_name!r}: "
            f"expected '<name>-<version>.dist-info'"
        )
    return name, version


def _parse_version(value: str, location: str) -> Version:
    try:
        return Version(value)
    except InvalidVersion:
        raise WheelValidationError(
            f"Invalid version {value!r} in {location}"
        ) from None


def _get_single_field(msg: Message, field: str, path: str) -> str:
    values = msg.get_all(field, [])
    if not values:
        raise WheelValidationError(
            f"Missing required {field!r} field in {path!r}"
        )
    if len(values) > 1:
        raise WheelValidationError(
            f"Duplicate {field!r} fields ({len(values)} occurrences: "
            f"{[str(v) for v in values]!r}) in {path!r}"
        )
    return str(values[0])


def _find_single_member(
    members: list[str], canonical: str, dist_info: str, filename: str
) -> str:
    candidates = [m for m in members if m.upper() == canonical]
    if not candidates:
        raise WheelValidationError(
            f"{filename}: missing {canonical} file in {dist_info!r}"
        )
    if len(candidates) > 1:
        raise WheelValidationError(
            f"{filename}: ambiguous wheel, multiple {canonical} candidates "
            f"in {dist_info!r}: {sorted(candidates)!r}"
        )
    return candidates[0]


def validate_wheel(file: StrPath) -> None:
    """Strictly validate that a wheel's metadata is internally consistent.

    Cross-checks the project name, version and compatibility tags between:

    * the wheel filename,
    * the single ``.dist-info`` directory in the archive,
    * the ``Name``/``Version`` fields of ``METADATA``, and
    * the ``Tag`` fields of ``WHEEL``.

    Names are compared after normalization per PEP 503, versions after
    parsing per PEP 440, and tags as expanded sets per PEP 425, so
    legitimate differences in case, separators or compressed tag notation
    are accepted. Archives with more than one ``.dist-info`` directory or
    more than one candidate ``RECORD``/``METADATA``/``WHEEL`` file are
    rejected as ambiguous.

    :param file: path to the wheel file to validate
    :raises WheelValidationError: if any consistency check fails
    """
    filename = os.path.basename(file)
    try:
        file_name, file_version, _build, file_tags = parse_wheel_filename(filename)
    except InvalidWheelFilename as exc:
        raise WheelValidationError(str(exc)) from None

    try:
        zf = ZipFile(file)
    except BadZipFile as exc:
        raise WheelValidationError(
            f"Cannot read wheel {filename!r}: {exc}"
        ) from None

    with zf:
        dist_infos = _dist_info_members(zf.namelist())
        if not dist_infos:
            raise WheelValidationError(
                f"{filename}: no .dist-info directory found in the archive"
            )
        if len(dist_infos) > 1:
            identities = {
                (canonicalize_name(name), version)
                for name, version in map(_split_dist_info, dist_infos)
            }
            if len(identities) == 1:
                raise WheelValidationError(
                    f"{filename}: ambiguous wheel, duplicate .dist-info "
                    f"directories that normalize to the same name and "
                    f"version: {sorted(dist_infos)!r}"
                )
            raise WheelValidationError(
                f"{filename}: conflicting .dist-info directories in the "
                f"archive: {sorted(dist_infos)!r}"
            )

        dist_info, members = next(iter(dist_infos.items()))
        dir_name, dir_version = _split_dist_info(dist_info)
        if canonicalize_name(dir_name) != file_name:
            raise WheelValidationError(
                f"{filename}: project name mismatch: filename says "
                f"{file_name!r} but the .dist-info directory is {dist_info!r}"
            )
        if _parse_version(dir_version, repr(dist_info)) != file_version:
            raise WheelValidationError(
                f"{filename}: version mismatch: filename says "
                f"{file_version!s} but the .dist-info directory is {dist_info!r}"
            )

        # Ensure there is exactly one RECORD, so that hash verification
        # cannot be ambiguous about which file is authoritative.
        _find_single_member(members, "RECORD", dist_info, filename)

        metadata_member = _find_single_member(
            members, "METADATA", dist_info, filename
        )
        metadata_path = f"{dist_info}/{metadata_member}"
        metadata = BytesParser(policy=email.policy.compat32).parsebytes(
            zf.read(metadata_path)
        )
        meta_name = _get_single_field(metadata, "Name", metadata_path)
        meta_version = _get_single_field(metadata, "Version", metadata_path)
        if canonicalize_name(meta_name) != file_name:
            raise WheelValidationError(
                f"{filename}: project name mismatch: filename says "
                f"{file_name!r} but 'Name' in {metadata_path!r} is {meta_name!r}"
            )
        if _parse_version(meta_version, metadata_path) != file_version:
            raise WheelValidationError(
                f"{filename}: version mismatch: filename says "
                f"{file_version!s} but 'Version' in {metadata_path!r} "
                f"is {meta_version!r}"
            )

        wheel_member = _find_single_member(members, "WHEEL", dist_info, filename)
        wheel_path = f"{dist_info}/{wheel_member}"
        wheel_meta = BytesParser(policy=email.policy.compat32).parsebytes(
            zf.read(wheel_path)
        )
        _get_single_field(wheel_meta, "Wheel-Version", wheel_path)
        tag_fields = wheel_meta.get_all("Tag", [])
        if not tag_fields:
            raise WheelValidationError(
                f"Missing required 'Tag' field in {wheel_path!r}"
            )
        wheel_tags = set()
        for tag in tag_fields:
            try:
                wheel_tags.update(parse_tag(str(tag)))
            except InvalidTag:
                raise WheelValidationError(
                    f"Invalid 'Tag' value {tag!r} in {wheel_path!r}"
                ) from None
        if wheel_tags != file_tags:
            only_filename = sorted(str(tag) for tag in file_tags - wheel_tags)
            only_wheel = sorted(str(tag) for tag in wheel_tags - file_tags)
            raise WheelValidationError(
                f"{filename}: tag mismatch between filename and "
                f"{wheel_path!r}: only in filename: "
                f"{only_filename or 'none'}; only in WHEEL: "
                f"{only_wheel or 'none'}"
            )
