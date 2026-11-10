from __future__ import annotations

import hashlib
import io
import stat
import sys
import zlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

import pytest
from pytest import MonkeyPatch, TempPathFactory
from wheel.wheelfile import (
    VerifyingReader,
    WheelError,
    WheelFile,
)


@pytest.fixture
def wheel_path(tmp_path: Path) -> Path:
    return tmp_path.joinpath("test-1.0-py2.py3-none-any.whl")


@pytest.mark.parametrize(
    "filename",
    [
        "foo-2-py3-none-any.whl",
        "foo-2-py2.py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
    ],
)
def test_wheelfile_re(filename: str, tmp_path: Path) -> None:
    # Regression test for #208 and #485
    path = tmp_path / filename
    with WheelFile(path, "w") as wf:
        assert wf.parsed_filename.group("namever") == "foo-2"


@pytest.mark.parametrize(
    "filename",
    [
        "test.whl",
        "test-1.0.whl",
        "test-1.0-py2.whl",
        "test-1.0-py2-none.whl",
        "test-1.0-py2-none-any",
        "test-1.0-py 2-none-any.whl",
    ],
)
def test_bad_wheel_filename(filename: str) -> None:
    exc = pytest.raises(WheelError, WheelFile, filename)
    exc.match(f"^Bad wheel filename {filename!r}$")


def test_missing_record(wheel_path: Path) -> None:
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, w0rld!")\n')

    exc = pytest.raises(WheelError, WheelFile, wheel_path)
    exc.match("^Missing test-1.0.dist-info/RECORD file$")


def test_mixed_case_dist_info(tmp_path: Path) -> None:
    """Regression test: wheel filename has uppercase but .dist-info dir is lowercase.

    A wheel named ``Django-3.2.5.whl`` may contain ``django-3.2.5.dist-info/``
    inside (normalized). WheelFile should find RECORD case-insensitively.
    See `#411 <https://github.com/pypa/wheel/issues/411>`_.
    """
    wheel_path = tmp_path / "MixedCase-1.0-py3-none-any.whl"
    with ZipFile(wheel_path, "w", ZIP_DEFLATED) as zf:
        zf.writestr("mixedcase/__init__.py", "")
        # Use lowercase dist-info (as pip/build tools produce)
        zf.writestr("mixedcase-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        zf.writestr(
            "mixedcase-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: MixedCase\nVersion: 1.0\n",
        )
        zf.writestr(
            "mixedcase-1.0.dist-info/RECORD",
            "mixedcase/__init__.py,,\n",
        )

    # Should not raise — this is the fix
    with WheelFile(wheel_path) as wf:
        assert wf.dist_info_path == "mixedcase-1.0.dist-info"
        assert wf.record_path == "mixedcase-1.0.dist-info/RECORD"


def test_unsupported_hash_algorithm(wheel_path: Path) -> None:
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, w0rld!")\n')
        zf.writestr(
            "test-1.0.dist-info/RECORD",
            "hello/héllö.py,sha000=bv-QV3RciQC2v3zL8Uvhd_arp40J5A9xmyubN34OVwo,25",
        )

    exc = pytest.raises(WheelError, WheelFile, wheel_path)
    exc.match("^Unsupported hash algorithm: sha000$")


@pytest.mark.parametrize(
    "algorithm, digest",
    [
        pytest.param("md5", "4J-scNa2qvSgy07rS4at-Q", id="md5"),
        pytest.param("sha1", "QjCnGu5Qucb6-vir1a6BVptvOA4", id="sha1"),
    ],
)
def test_weak_hash_algorithm(wheel_path: Path, algorithm: str, digest: str) -> None:
    hash_string = f"{algorithm}={digest}"
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, w0rld!")\n')
        zf.writestr("test-1.0.dist-info/RECORD", f"hello/héllö.py,{hash_string},25")

    exc = pytest.raises(WheelError, WheelFile, wheel_path)
    exc.match(rf"^Weak hash algorithm \({algorithm}\) is not permitted by PEP 427$")


@pytest.mark.parametrize(
    "algorithm, digest",
    [
        pytest.param(
            "sha256", "bv-QV3RciQC2v3zL8Uvhd_arp40J5A9xmyubN34OVwo", id="sha256"
        ),
        pytest.param(
            "sha384",
            "cDXriAy_7i02kBeDkN0m2RIDz85w6pwuHkt2PZ4VmT2PQc1TZs8Ebvf6eKDFcD_S",
            id="sha384",
        ),
        pytest.param(
            "sha512",
            "kdX9CQlwNt4FfOpOKO_X0pn_v1opQuksE40SrWtMyP1NqooWVWpzCE3myZTfpy8g2azZON_"
            "iLNpWVxTwuDWqBQ",
            id="sha512",
        ),
    ],
)
def test_testzip(wheel_path: Path, algorithm: str, digest: str) -> None:
    hash_string = f"{algorithm}={digest}"
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, world!")\n')
        zf.writestr("test-1.0.dist-info/RECORD", f"hello/héllö.py,{hash_string},25")

    with WheelFile(wheel_path) as wf:
        wf.testzip()


def test_testzip_missing_hash(wheel_path: Path) -> None:
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, world!")\n')
        zf.writestr("test-1.0.dist-info/RECORD", "")

    with WheelFile(wheel_path) as wf:
        exc = pytest.raises(WheelError, wf.testzip)
        exc.match("^No hash found for file 'hello/héllö.py'$")


def test_testzip_bad_hash(wheel_path: Path) -> None:
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, w0rld!")\n')
        zf.writestr(
            "test-1.0.dist-info/RECORD",
            "hello/héllö.py,sha256=bv-QV3RciQC2v3zL8Uvhd_arp40J5A9xmyubN34OVwo,25",
        )

    with WheelFile(wheel_path) as wf:
        exc = pytest.raises(WheelError, wf.testzip)
        exc.match("^Hash mismatch for file 'hello/héllö.py'$")


def test_write_str(wheel_path: Path) -> None:
    with WheelFile(wheel_path, "w") as wf:
        wf.writestr("hello/héllö.py", 'print("Héllö, world!")\n')
        wf.writestr("hello/h,ll,.py", 'print("Héllö, world!")\n')

    with ZipFile(wheel_path, "r") as zf:
        infolist = zf.infolist()
        assert len(infolist) == 3
        assert infolist[0].filename == "hello/héllö.py"
        assert infolist[0].file_size == 25
        assert infolist[1].filename == "hello/h,ll,.py"
        assert infolist[1].file_size == 25
        assert infolist[2].filename == "test-1.0.dist-info/RECORD"

        record = zf.read("test-1.0.dist-info/RECORD")
        assert record.decode("utf-8") == (
            "hello/héllö.py,sha256=bv-QV3RciQC2v3zL8Uvhd_arp40J5A9xmyubN34OVwo,25\n"
            '"hello/h,ll,.py",sha256=bv-QV3RciQC2v3zL8Uvhd_arp40J5A9xmyubN34OVwo,25\n'
            "test-1.0.dist-info/RECORD,,\n"
        )


def test_timestamp(
    tmp_path_factory: TempPathFactory, wheel_path: Path, monkeypatch: MonkeyPatch
) -> None:
    # An environment variable can be used to influence the timestamp on
    # TarInfo objects inside the zip.  See issue #143.
    build_dir = tmp_path_factory.mktemp("build")
    for filename in ("one", "two", "three"):
        build_dir.joinpath(filename).write_text(filename + "\n", encoding="utf-8")

    # The earliest date representable in TarInfos, 1980-01-01
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "315576060")

    with WheelFile(wheel_path, "w") as wf:
        wf.write_files(str(build_dir))

    with ZipFile(wheel_path, "r") as zf:
        for info in zf.infolist():
            assert info.date_time[:3] == (1980, 1, 1)
            assert info.compress_type == ZIP_DEFLATED


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows does not support UNIX-like permissions"
)
def test_attributes(tmp_path_factory: TempPathFactory, wheel_path: Path) -> None:
    # With the change from ZipFile.write() to .writestr(), we need to manually
    # set member attributes.
    build_dir = tmp_path_factory.mktemp("build")
    files = (("foo", 0o644), ("bar", 0o755))
    for filename, mode in files:
        path = build_dir.joinpath(filename)
        path.write_text(filename + "\n", encoding="utf-8")
        path.chmod(mode)

    with WheelFile(wheel_path, "w") as wf:
        wf.write_files(str(build_dir))

    with ZipFile(wheel_path, "r") as zf:
        for filename, mode in files:
            info = zf.getinfo(filename)
            assert info.external_attr == (mode | stat.S_IFREG) << 16
            assert info.compress_type == ZIP_DEFLATED

        info = zf.getinfo("test-1.0.dist-info/RECORD")
        assert info.external_attr == (0o664 | stat.S_IFREG) << 16


# ---------------------------------------------------------------------------
# VerifyingReader / WheelFile.open() verification behavior
# ---------------------------------------------------------------------------


MEMBER_NAME = "hello/héllö.py"
MEMBER_DATA = b'print("H\xe9ll\xf6, world!")\n'


def _record_line(name: str, data: bytes, size: int | None = None) -> str:
    digest = urlsafe_hash(data)
    actual_size = len(data) if size is None else size
    return f"{name},sha256={digest},{actual_size}\n"


def urlsafe_hash(data: bytes) -> str:
    import base64

    return (
        base64.urlsafe_b64encode(hashlib.sha256(data).digest())
        .rstrip(b"=")
        .decode("ascii")
    )


def _build_wheel(
    wheel_path: Path,
    *,
    members: dict[str, bytes] | None = None,
    record: str | None = None,
    compression: int = ZIP_DEFLATED,
) -> Path:
    members = {MEMBER_NAME: MEMBER_DATA} if members is None else members
    if record is None:
        record = "".join(_record_line(name, data) for name, data in members.items())

    with ZipFile(wheel_path, "w", compression) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
        zf.writestr("test-1.0.dist-info/RECORD", record)

    return wheel_path


class CountingMember(io.BytesIO):
    """BytesIO that counts close() calls and exposes read1()."""

    def __init__(self, data: bytes = b"", *, seekable_stream: bool = True):
        super().__init__(data)
        self.close_count = 0
        self._seekable_stream = seekable_stream

    def read1(self, size: int = -1) -> bytes:
        return self.read(size)

    def seekable(self) -> bool:
        return self._seekable_stream

    def close(self) -> None:
        self.close_count += 1
        super().close()


def _reader(
    member: io.BytesIO,
    data: bytes,
    *,
    expected_hash: bytes | None = None,
    algorithm: str | None = "sha256",
    expected_size: int | None = None,
    expected_crc: int | None = None,
) -> VerifyingReader:
    if expected_hash is None and algorithm is not None:
        expected_hash = hashlib.sha256(data).digest()
    if expected_size is None:
        expected_size = len(data)
    if expected_crc is None:
        expected_crc = zlib.crc32(data)
    return VerifyingReader(
        member,
        "member",
        file_size=len(data),
        expected_hash=expected_hash,
        hash_algorithm=algorithm,
        expected_size=expected_size,
        expected_crc=expected_crc,
    )


def test_open_returns_verifying_reader(wheel_path: Path) -> None:
    _build_wheel(wheel_path)
    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            assert isinstance(member, VerifyingReader)
            assert member.readable()
            assert not member.writable()
            assert member.seekable()


@pytest.mark.parametrize("read_size", [1, 2, 5, 16, 64, 4096, -1, None])
def test_read_sizes_and_verified(wheel_path: Path, read_size: int) -> None:
    _build_wheel(wheel_path)
    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            assert not member.verified
            chunks: list[bytes] = []
            while True:
                chunk = member.read(read_size)
                if not chunk:
                    break
                chunks.append(chunk)
            assert b"".join(chunks) == MEMBER_DATA
            assert member.verified


@pytest.mark.parametrize("chunk_size", [1, 3, 17, 128, -1])
def test_read1_readinto_iteration(wheel_path: Path, chunk_size: int) -> None:
    _build_wheel(wheel_path)
    with WheelFile(wheel_path) as wf:
        # read1 loop
        with wf.open(MEMBER_NAME) as member:
            collected = b"".join(iter(lambda: member.read1(chunk_size), b""))
            assert collected == MEMBER_DATA
            assert member.verified

        # readinto loop
        with wf.open(MEMBER_NAME) as member:
            size = max(chunk_size, 1) if chunk_size > 0 else 64
            buffer = bytearray(size)
            collected = b""
            view = memoryview(buffer)
            while True:
                written = member.readinto(view)
                if not written:
                    break
                collected += bytes(view[:written])
            assert collected == MEMBER_DATA
            assert member.verified

        # line iteration
        with wf.open(MEMBER_NAME) as member:
            assert b"".join(member) == MEMBER_DATA
            assert member.verified


def test_readline_without_newline_verifies() -> None:
    data = b"no newline here"
    reader = _reader(CountingMember(data), data)
    assert reader.readline() == data
    assert reader.verified


def test_partial_read_is_not_verified(wheel_path: Path) -> None:
    _build_wheel(wheel_path)
    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            member.read(4)
            assert not member.verified
            assert member.read() == MEMBER_DATA[4:]
            assert member.verified


def test_early_close_not_verified_and_released_once(wheel_path: Path) -> None:
    _build_wheel(wheel_path)
    with WheelFile(wheel_path) as wf:
        member = wf.open(MEMBER_NAME)
        member.read(3)
        member.close()
        assert member.closed
        assert not member.verified
        # Idempotent close must not touch the underlying stream a second time
        member.close()
        assert member._member.closed
        pytest.raises(ValueError, member.read)
        pytest.raises(ValueError, member.seek, 0)


def test_context_manager_closes_and_verifies(wheel_path: Path) -> None:
    _build_wheel(wheel_path)
    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            assert member.read() == MEMBER_DATA
        assert member.closed
        assert member.verified


def test_underlying_close_called_once() -> None:
    data = b"release me"
    raw = CountingMember(data)
    reader = _reader(raw, data)
    with reader:
        reader.read(2)
        reader.close()
    assert raw.close_count == 1
    assert not reader.verified


def test_seek_forward_and_to_end_verifies(wheel_path: Path) -> None:
    _build_wheel(wheel_path)
    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            member.seek(10)
            assert member.tell() == 10
            member.seek(5, io.SEEK_CUR)
            assert member.tell() == 15
            assert member.read() == MEMBER_DATA[15:]
            assert member.verified

        # jump straight to the end: skipped bytes are hashed too
        with wf.open(MEMBER_NAME) as member:
            assert member.seek(0, io.SEEK_END) == len(MEMBER_DATA)
            assert member.tell() == len(MEMBER_DATA)
            assert member.verified


def test_seek_backward_restarts_verification(wheel_path: Path) -> None:
    _build_wheel(wheel_path)
    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            member.read(10)
            member.seek(0)
            assert member.tell() == 0
            assert not member.verified
            assert member.read() == MEMBER_DATA
            assert member.verified

        # seek backward to a middle position
        with wf.open(MEMBER_NAME) as member:
            member.seek(0, io.SEEK_END)
            assert member.verified
            member.seek(7)
            assert not member.verified
            assert member.read() == MEMBER_DATA[7:]
            assert member.verified


def test_seek_clamps_and_rejects_bad_whence(wheel_path: Path) -> None:
    _build_wheel(wheel_path)
    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            assert member.seek(10**9) == len(MEMBER_DATA)
            assert member.seek(-(10**9)) == 0
            pytest.raises(ValueError, member.seek, 0, 42)
            assert member.seek(-10, io.SEEK_END) == len(MEMBER_DATA) - 10
            member.seek(0)
            assert member.read() == MEMBER_DATA
            assert member.verified


def test_seek_unsupported_on_non_seekable_stream() -> None:
    data = b"forward only"
    reader = _reader(CountingMember(data, seekable_stream=False), data)
    assert not reader.seekable()
    pytest.raises(io.UnsupportedOperation, reader.seek, 0)
    # reading still works and verifies
    assert reader.read() == data
    assert reader.verified


def test_bad_digest_raises_wheel_error(wheel_path: Path) -> None:
    bad_digest = "A" * 43
    _build_wheel(
        wheel_path,
        record=f"{MEMBER_NAME},sha256={bad_digest},{len(MEMBER_DATA)}\n",
    )
    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            assert not member.verified
            exc = pytest.raises(WheelError, member.read)
            exc.match(f"^Hash mismatch for file '{MEMBER_NAME}'$")
            assert not member.verified


def test_bad_declared_size_raises_wheel_error(wheel_path: Path) -> None:
    _build_wheel(
        wheel_path,
        record=_record_line(MEMBER_NAME, MEMBER_DATA, size=len(MEMBER_DATA) + 7),
    )
    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            exc = pytest.raises(WheelError, member.read)
            exc.match(r"^Size mismatch for file '")
            assert not member.verified


def test_bad_crc_raises_wheel_error() -> None:
    data = b"checksum me"
    reader = _reader(CountingMember(data), data, expected_crc=0xDEADBEEF)
    exc = pytest.raises(WheelError, reader.read)
    exc.match(r"^Bad CRC-32 for file 'member'$")
    assert not reader.verified


def test_crc_checked_after_forward_seek_on_stored_member(wheel_path: Path) -> None:
    data = b"abcdefghij"
    digest = urlsafe_hash(data)
    with ZipFile(wheel_path, "w", ZIP_STORED) as zf:
        zf.writestr(MEMBER_NAME, data)
        zf.writestr(
            "test-1.0.dist-info/RECORD",
            f"{MEMBER_NAME},sha256={digest},{len(data)}\n",
        )

    # Flip a payload byte while leaving the central-directory CRC untouched
    raw = bytearray(wheel_path.read_bytes())
    index = raw.find(b"PK\x03\x04")
    data_offset = index + 30 + len(MEMBER_NAME.encode("utf-8"))
    raw[data_offset + 3] ^= 0xFF
    wheel_path.write_bytes(raw)

    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            # stdlib disables its own CRC on the fast stored-member seek; the
            # wrapper must still detect the corruption itself
            with pytest.raises(WheelError, match="CRC-32"):
                member.seek(0, io.SEEK_END)
            assert not member.verified


def test_integrity_error_wrapped_with_cause() -> None:
    from zipfile import BadZipFile

    class BrokenMember(CountingMember):
        def read1(self, size: int = -1) -> bytes:
            raise BadZipFile("simulated corruption")

    reader = _reader(BrokenMember(b""), b"abc")
    exc = pytest.raises(WheelError, reader.read)
    assert isinstance(exc.value.__cause__, BadZipFile)


def test_generic_read_error_preserved() -> None:
    class BrokenMember(CountingMember):
        def read1(self, size: int = -1) -> bytes:
            raise OSError("simulated IO failure")

    reader = _reader(BrokenMember(b""), b"abc")
    with pytest.raises(OSError, match="simulated IO failure"):
        reader.read()
    assert not reader.verified


def test_record_and_signature_members_are_exempt(wheel_path: Path) -> None:
    record = _record_line(MEMBER_NAME, MEMBER_DATA)
    _build_wheel(
        wheel_path,
        members={
            MEMBER_NAME: MEMBER_DATA,
            "test-1.0.dist-info/RECORD.jws": b"signature",
        },
        record=record,
    )
    with WheelFile(wheel_path) as wf:
        for name in (
            wf.record_path,
            wf.record_path + ".jws",
        ):
            with wf.open(name) as member:
                assert member.read()
                assert member.verified


def test_empty_member_verifies_immediately() -> None:
    reader = _reader(CountingMember(b""), b"")
    assert reader.read() == b""
    assert reader.verified
    assert reader.read(5) == b""
    assert reader.verified


def test_read_zero_and_closed_operations() -> None:
    data = b"abc"
    reader = _reader(CountingMember(data), data)
    assert reader.read(0) == b""
    assert reader.read1(0) == b""
    assert reader.readline(0) == b""
    assert not reader.verified
    assert reader.readinto(bytearray(0)) == 0


def test_verification_status_example(wheel_path: Path) -> None:
    _build_wheel(wheel_path)
    with WheelFile(wheel_path) as wf:
        with wf.open(MEMBER_NAME) as member:
            data = member.read()
            if not member.verified:
                raise WheelError("member was not fully verified")
        assert data == MEMBER_DATA
