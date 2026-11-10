from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

import pytest

from wheel.validate import WheelValidationError, validate_wheel
from wheel.wheelfile import WheelFile


def make_wheel(
    path: Path,
    *,
    dist_info: str = "demo-1.0.dist-info",
    name: str = "demo",
    version: str = "1.0",
    tags: tuple[str, ...] = ("py3-none-any",),
    extra_members: dict[str, str] | None = None,
    record: bool = True,
) -> Path:
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    wheel = (
        "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
        + "".join(f"Tag: {tag}\n" for tag in tags)
    )
    with ZipFile(path, "w") as zf:
        zf.writestr(f"{dist_info}/METADATA", metadata)
        zf.writestr(f"{dist_info}/WHEEL", wheel)
        if record:
            zf.writestr(f"{dist_info}/RECORD", "")
        for arcname, data in (extra_members or {}).items():
            zf.writestr(arcname, data)
    return path


def test_valid_wheel_with_normalized_metadata(tmp_path: Path) -> None:
    # Legal case/separator differences and PEP 440-equivalent versions
    # must not be reported as mismatches.
    path = make_wheel(
        tmp_path / "My_Pkg-1.0-py3-none-any.whl",
        dist_info="my.pkg-1.0.0.dist-info",
        name="My-Pkg",
        version="1.0.0",
    )
    validate_wheel(path)


def test_valid_wheel_with_compressed_tags(tmp_path: Path) -> None:
    # The compressed filename tag set expands to the same tags listed in WHEEL.
    path = make_wheel(
        tmp_path / "demo-1.0-py2.py3-none-any.whl",
        tags=("py2-none-any", "py3-none-any"),
    )
    validate_wheel(path)


def test_name_impersonation_rejected(tmp_path: Path) -> None:
    path = make_wheel(
        tmp_path / "evil-1.0-py3-none-any.whl",
        dist_info="real-1.0.dist-info",
        name="real",
    )
    exc = pytest.raises(WheelValidationError, validate_wheel, path)
    exc.match("project name mismatch")
    exc.match("'real-1.0.dist-info'")


def test_version_mismatch_rejected(tmp_path: Path) -> None:
    path = make_wheel(tmp_path / "demo-1.0-py3-none-any.whl", version="2.0")
    exc = pytest.raises(WheelValidationError, validate_wheel, path)
    exc.match("version mismatch")
    exc.match("demo-1.0.dist-info/METADATA")


def test_tag_set_mismatch_rejected(tmp_path: Path) -> None:
    # Filename claims py2.py3 but WHEEL only lists py3: the expanded sets
    # differ even though no raw string comparison would flag a subset.
    path = make_wheel(
        tmp_path / "demo-1.0-py2.py3-none-any.whl", tags=("py3-none-any",)
    )
    exc = pytest.raises(WheelValidationError, validate_wheel, path)
    exc.match("tag mismatch")
    exc.match("py2-none-any")


def test_extra_tag_in_wheel_file_rejected(tmp_path: Path) -> None:
    path = make_wheel(
        tmp_path / "demo-1.0-py3-none-any.whl",
        tags=("py3-none-any", "py2-none-any"),
    )
    exc = pytest.raises(WheelValidationError, validate_wheel, path)
    exc.match("tag mismatch")
    exc.match("only in WHEEL")


def test_multiple_dist_info_rejected(tmp_path: Path) -> None:
    path = make_wheel(
        tmp_path / "demo-1.0-py3-none-any.whl",
        extra_members={
            "other-2.0.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: other\nVersion: 2.0\n"
            ),
            "other-2.0.dist-info/RECORD": "",
        },
    )
    exc = pytest.raises(WheelValidationError, validate_wheel, path)
    exc.match("conflicting .dist-info directories")
    exc.match("other-2.0.dist-info")


def test_duplicate_normalized_dist_info_rejected(tmp_path: Path) -> None:
    path = make_wheel(
        tmp_path / "demo-1.0-py3-none-any.whl",
        extra_members={
            "DEMO-1.0.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"
            ),
            "DEMO-1.0.dist-info/RECORD": "",
        },
    )
    exc = pytest.raises(WheelValidationError, validate_wheel, path)
    exc.match("duplicate .dist-info directories")


def test_multiple_record_candidates_rejected(tmp_path: Path) -> None:
    path = make_wheel(
        tmp_path / "demo-1.0-py3-none-any.whl",
        extra_members={"demo-1.0.dist-info/record": ""},
    )
    exc = pytest.raises(WheelValidationError, validate_wheel, path)
    exc.match("multiple RECORD candidates")


def test_missing_name_field_reports_location(tmp_path: Path) -> None:
    path = tmp_path / "demo-1.0-py3-none-any.whl"
    with ZipFile(path, "w") as zf:
        zf.writestr("demo-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nVersion: 1.0\n")
        zf.writestr(
            "demo-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        zf.writestr("demo-1.0.dist-info/RECORD", "")
    exc = pytest.raises(WheelValidationError, validate_wheel, path)
    exc.match(r"Missing required 'Name' field in 'demo-1.0.dist-info/METADATA'")


def test_duplicate_version_field_reports_location(tmp_path: Path) -> None:
    path = tmp_path / "demo-1.0-py3-none-any.whl"
    with ZipFile(path, "w") as zf:
        zf.writestr(
            "demo-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nVersion: 1.0\n",
        )
        zf.writestr(
            "demo-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        zf.writestr("demo-1.0.dist-info/RECORD", "")
    exc = pytest.raises(WheelValidationError, validate_wheel, path)
    exc.match(r"Duplicate 'Version' fields .* in 'demo-1.0.dist-info/METADATA'")


def test_missing_dist_info_rejected(tmp_path: Path) -> None:
    path = tmp_path / "demo-1.0-py3-none-any.whl"
    with ZipFile(path, "w") as zf:
        zf.writestr("demo/__init__.py", "")
    exc = pytest.raises(WheelValidationError, validate_wheel, path)
    exc.match("no .dist-info directory")


def test_lenient_reader_still_accepts_lenient_wheels(tmp_path: Path) -> None:
    # A wheel that fails the strict check (tag mismatch) can still be read
    # through the existing lenient interface.
    path = make_wheel(
        tmp_path / "demo-1.0-py2.py3-none-any.whl", tags=("py3-none-any",)
    )
    with WheelFile(path) as wf:
        assert wf.dist_info_path == "demo-1.0.dist-info"
    pytest.raises(WheelValidationError, validate_wheel, path)
