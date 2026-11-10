from __future__ import annotations

import base64
import builtins
import csv
import hashlib
import io
import stat
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile, ZipInfo

import pytest
from pytest import MonkeyPatch, TempPathFactory

from wheel.wheelfile import CHUNK_SIZE, WheelError, WheelFile


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


class RecordingBytesReader(io.BytesIO):
    """In-memory file stand-in that records the size of every read() request.

    The descriptor comes from the real source file so ``os.fstat`` (used for
    permissions and the timestamp) keeps working unchanged.
    """

    def __init__(self, data: bytes, source: Path) -> None:
        super().__init__(data)
        self._real_file = source.open("rb")
        self.read_sizes: list[int] = []
        self.delivered_sizes: list[int] = []

    def fileno(self) -> int:
        return self._real_file.fileno()

    def close(self) -> None:
        self._real_file.close()
        super().close()

    def read(self, size: int = -1) -> bytes:
        chunk = super().read(size)
        if chunk:
            self.read_sizes.append(size)
            self.delivered_sizes.append(len(chunk))
        return chunk


class FailingChunkReader(RecordingBytesReader):
    """Fails on the second chunk read, after one full chunk was streamed."""

    def read(self, size: int = -1) -> bytes:
        recorded = len(self.read_sizes)
        chunk = super().read(size)
        if recorded == 1 and chunk:
            raise OSError("simulated read failure on second chunk")
        return chunk


def _patch_open(
    monkeypatch: MonkeyPatch, source: Path, reader: RecordingBytesReader
) -> None:
    real_open = builtins.open

    def fake_open(path: object, *args: object, **kwargs: object) -> object:
        if str(path) == str(source):
            return reader
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)


def test_write_streams_bounded_chunks(
    tmp_path: Path, wheel_path: Path, monkeypatch: MonkeyPatch
) -> None:
    # 2.5 chunks worth of data: two full reads plus a short final one, well
    # below any "huge file" threshold.
    payload = bytes((i % 251 for i in range(2 * CHUNK_SIZE + 1024)))
    source = tmp_path / "model.bin"
    source.write_bytes(payload)
    reader = RecordingBytesReader(payload, source)
    _patch_open(monkeypatch, source, reader)

    with WheelFile(wheel_path, "w") as wf:
        wf.write(str(source), "data/model.bin")

    # Every read must be bounded by the chunk size; no whole-file reads.
    assert reader.read_sizes
    assert max(reader.read_sizes) <= CHUNK_SIZE
    assert reader.read_sizes == [CHUNK_SIZE, CHUNK_SIZE, CHUNK_SIZE]
    assert reader.delivered_sizes == [CHUNK_SIZE, CHUNK_SIZE, 1024]

    # Independently verify every byte, the hash and the size with plain
    # zipfile/hashlib, then cross-check them against RECORD.
    expected_digest = hashlib.sha256(payload).digest()
    with ZipFile(wheel_path) as zf:
        assert zf.namelist() == [
            "data/model.bin",
            "test-1.0.dist-info/RECORD",
        ]
        info = zf.getinfo("data/model.bin")
        assert info.file_size == len(payload)
        assert info.compress_type == ZIP_DEFLATED
        assert info.external_attr == (0o644 | stat.S_IFREG) << 16
        stored = zf.read("data/model.bin")
        assert stored == payload
        assert hashlib.sha256(stored).digest() == expected_digest

        record_rows = list(
            csv.reader(io.TextIOWrapper(zf.open("test-1.0.dist-info/RECORD")))
        )

    record = {row[0]: row[1:] for row in record_rows}
    algorithm, digest = record["data/model.bin"][0].split("=", 1)
    assert algorithm == "sha256"
    pad = "=" * (-len(digest) % 4)
    assert base64.urlsafe_b64decode(digest + pad) == expected_digest
    assert int(record["data/model.bin"][1]) == len(payload)
    assert record["test-1.0.dist-info/RECORD"] == ["", ""]


def test_write_preserves_compression_and_stored_mode(
    tmp_path: Path, wheel_path: Path, monkeypatch: MonkeyPatch
) -> None:
    payload = b"uncompressed" * 1000
    source = tmp_path / "blob.bin"
    source.write_bytes(payload)
    reader = RecordingBytesReader(payload, source)
    _patch_open(monkeypatch, source, reader)

    with WheelFile(wheel_path, "w") as wf:
        wf.write(str(source), "blob.bin", compress_type=ZIP_STORED)

    with ZipFile(wheel_path) as zf:
        info = zf.getinfo("blob.bin")
        assert info.compress_type == ZIP_STORED
        assert info.file_size == len(payload)
        assert zf.read("blob.bin") == payload
        assert max(reader.read_sizes) <= CHUNK_SIZE


def test_write_hash_tracks_streamed_bytes_when_source_changes(
    tmp_path: Path, wheel_path: Path, monkeypatch: MonkeyPatch
) -> None:
    payload = bytes((i % 251 for i in range(CHUNK_SIZE + 512)))
    source = tmp_path / "model.bin"
    source.write_bytes(payload)
    reader = RecordingBytesReader(payload, source)
    _patch_open(monkeypatch, source, reader)

    original_read = reader.read

    def tamper_on_first_chunk(size: int = -1) -> bytes:
        chunk = original_read(size)
        if len(reader.read_sizes) == 1:
            # Overwrite the source with different content while streaming.
            source.write_bytes(b"totally different content" * 100)
        return chunk

    reader.read = tamper_on_first_chunk  # type: ignore[method-assign]

    with WheelFile(wheel_path, "w") as wf:
        wf.write(str(source), "data/model.bin")

    # RECORD must describe the bytes that were actually streamed, not the
    # tampered file now sitting on disk.
    expected_digest = hashlib.sha256(payload).digest()
    with ZipFile(wheel_path) as zf:
        stored = zf.read("data/model.bin")
        assert stored == payload
        assert hashlib.sha256(stored).digest() == expected_digest
        rows = list(
            csv.reader(io.TextIOWrapper(zf.open("test-1.0.dist-info/RECORD")))
        )

    record = {row[0]: row[1:] for row in rows}
    _, digest = record["data/model.bin"][0].split("=", 1)
    pad = "=" * (-len(digest) % 4)
    assert base64.urlsafe_b64decode(digest + pad) == expected_digest
    assert int(record["data/model.bin"][1]) == len(payload)


def test_write_read_failure_poisons_session(
    tmp_path: Path, wheel_path: Path, monkeypatch: MonkeyPatch
) -> None:
    payload = bytes((i % 251 for i in range(2 * CHUNK_SIZE + 1024)))
    source = tmp_path / "model.bin"
    source.write_bytes(payload)
    reader = FailingChunkReader(payload, source)
    _patch_open(monkeypatch, source, reader)

    wf = WheelFile(wheel_path, "w")
    with pytest.raises(OSError, match="simulated read failure"):
        wf.write(str(source), "data/model.bin")
    assert wf._failed is True

    # A corrupted session cannot accept more members through either entry.
    with pytest.raises(WheelError, match="failed state"):
        wf.write(str(source), "other.bin")
    with pytest.raises(WheelError, match="failed state"):
        wf.writestr("small.txt", b"payload")

    # Close must not fabricate a RECORD; it stays idempotent and does not raise.
    wf.close()
    wf.close()
    assert wf.fp is None

    # The leftover file is visibly broken rather than a plausible full wheel.
    with pytest.raises(BadZipFile):
        with ZipFile(wheel_path) as zf:
            zf.namelist()


def test_write_failure_inside_context_manager(
    tmp_path: Path, wheel_path: Path, monkeypatch: MonkeyPatch
) -> None:
    payload = b"x" * (2 * CHUNK_SIZE)

    class TruncatingReader(RecordingBytesReader):
        def read(self, size: int = -1) -> bytes:
            chunk = super().read(size)
            if len(self.read_sizes) == 2 and chunk:
                raise OSError("source vanished mid-read")
            return chunk

    source = tmp_path / "model.bin"
    source.write_bytes(payload)
    reader = TruncatingReader(payload, source)
    _patch_open(monkeypatch, source, reader)

    with pytest.raises(OSError, match="source vanished"):
        with WheelFile(wheel_path, "w") as wf:
            wf.write(str(source), "data/model.bin")

    with pytest.raises(BadZipFile):
        with ZipFile(wheel_path) as zf:
            zf.namelist()


@pytest.mark.parametrize(
    "second_call",
    [
        pytest.param(
            lambda wf, source: wf.write(str(source), "dup.bin"), id="write"
        ),
        pytest.param(
            lambda wf, source: wf.writestr("dup.bin", b"second"), id="writestr"
        ),
        pytest.param(
            lambda wf, source: wf.writestr(ZipInfo("dup.bin"), b"second"),
            id="writestr-zinfo",
        ),
    ],
)
def test_duplicate_member_rejected_consistently(
    tmp_path: Path,
    wheel_path: Path,
    monkeypatch: MonkeyPatch,
    second_call: object,
) -> None:
    payload = b"first member"
    source = tmp_path / "dup.bin"
    source.write_bytes(payload)
    reader = RecordingBytesReader(payload, source)
    _patch_open(monkeypatch, source, reader)

    with WheelFile(wheel_path, "w") as wf:
        wf.write(str(source), "dup.bin")
        with pytest.raises(
            WheelError, match="Duplicate name in archive: 'dup.bin'"
        ):
            second_call(wf, source)  # type: ignore[operator]

    # Only the first member plus RECORD made it into the archive.
    with ZipFile(wheel_path) as zf:
        assert zf.namelist() == ["dup.bin", "test-1.0.dist-info/RECORD"]
        assert zf.read("dup.bin") == payload


def test_duplicate_member_from_writestr(
    tmp_path: Path, wheel_path: Path, monkeypatch: MonkeyPatch
) -> None:
    payload = b"also a file"
    source = tmp_path / "unused.bin"
    source.write_bytes(payload)
    reader = RecordingBytesReader(payload, source)
    _patch_open(monkeypatch, source, reader)

    with WheelFile(wheel_path, "w") as wf:
        wf.writestr("dup.bin", b"first")
        with pytest.raises(
            WheelError, match="Duplicate name in archive: 'dup.bin'"
        ):
            wf.write(str(source), "dup.bin")
        with pytest.raises(
            WheelError, match="Duplicate name in archive: 'dup.bin'"
        ):
            wf.writestr("dup.bin", b"second")


def test_repeated_close_is_idempotent(wheel_path: Path) -> None:
    wf = WheelFile(wheel_path, "w")
    wf.writestr("hello.py", b"print('hi')\n")
    wf.close()
    wf.close()

    with ZipFile(wheel_path) as zf:
        assert zf.namelist() == ["hello.py", "test-1.0.dist-info/RECORD"]
