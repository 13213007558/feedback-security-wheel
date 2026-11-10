from __future__ import annotations

__all__ = [
    "WHEEL_INFO_RE",
    "VerifyingReader",
    "WheelError",
    "WheelFile",
]

import base64
import csv
import hashlib
import io
import logging
import os.path
import re
import stat
import time
import zlib
from io import BufferedIOBase, StringIO, TextIOWrapper
from typing import IO, TYPE_CHECKING, Literal
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile, ZipInfo

if TYPE_CHECKING:
    from _typeshed import SizedBuffer, StrPath

# Exceptions raised by the underlying stream when the compressed data itself is
# damaged.  They are re-raised as :class:`WheelError` while keeping the original
# exception as the cause.
_INTEGRITY_ERRORS: tuple[type[BaseException], ...] = (BadZipFile, zlib.error)


# Non-greedy matching of an optional build number may be too clever (more
# invalid wheel filenames will match). Separate regex for .dist-info?
WHEEL_INFO_RE = re.compile(
    r"""^(?P<namever>(?P<name>[^\s-]+?)-(?P<ver>[^\s-]+?))(-(?P<build>\d[^\s-]*))?
     -(?P<pyver>[^\s-]+?)-(?P<abi>[^\s-]+?)-(?P<plat>\S+)\.whl$""",
    re.VERBOSE,
)
MINIMUM_TIMESTAMP = 315532800  # 1980-01-01 00:00:00 UTC

log = logging.getLogger("wheel")


class WheelError(Exception):
    pass


def urlsafe_b64encode(data: bytes) -> bytes:
    """urlsafe_b64encode without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def urlsafe_b64decode(data: bytes) -> bytes:
    """urlsafe_b64decode without padding"""
    pad = b"=" * (4 - (len(data) & 3))
    return base64.urlsafe_b64decode(data + pad)


def get_zipinfo_datetime(
    timestamp: float | None = None,
) -> tuple[int, int, int, int, int]:
    # Some applications need reproducible .whl files, but they can't do this without
    # forcing the timestamp of the individual ZipInfo objects. See issue #143.
    timestamp = int(os.environ.get("SOURCE_DATE_EPOCH", timestamp or time.time()))
    timestamp = max(timestamp, MINIMUM_TIMESTAMP)
    return time.gmtime(timestamp)[0:6]


class VerifyingReader(BufferedIOBase):
    """Read a wheel member through the public binary IO interface while
    verifying its integrity.

    The wrapper only relies on the public :class:`~io.BufferedIOBase` interface
    of the stream returned by :meth:`zipfile.ZipFile.open`; it never touches the
    private internals of :class:`~zipfile.ZipExtFile`.  As bytes are read it
    independently computes:

    * the digest declared in ``RECORD`` (skipped for members exempted by the
      wheel specification),
    * the size declared in ``RECORD`` (when present), and
    * the ZIP CRC-32 checksum declared by the archive member.

    All three are compared once the end of the member is reached.

    Behavior:

    * Sequential reads (``read``, ``read1``, ``readinto``, ``readline`` and
      iteration) update the running checksums and verify the member when EOF is
      observed.
    * Forward seeks, including relative and ``SEEK_END`` seeks, read and hash
      every skipped byte, so a seek to the end still verifies the member.
    * Backward seeks reset the member and the checksums; verification restarts
      from the new position and remains possible until EOF is reached again.
    * Closing the reader before EOF releases the underlying stream but does not
      verify it; :attr:`verified` stays ``False``.
    * Unsupported moves (a non-seekable underlying stream) raise
      :class:`io.UnsupportedOperation`, matching the standard library.

    Integrity failures are raised as :class:`WheelError`.  Exceptions produced
    by the underlying stream while reading are re-raised unchanged unless they
    indicate damaged archive data, in which case they are wrapped in
    :class:`WheelError` with the original exception preserved as ``__cause__``.

    Example::

        with WheelFile("dist-1.0-py3-none-any.whl") as wf:
            with wf.open("dist/__init__.py") as member:
                data = member.read()
                if not member.verified:
                    raise WheelError("member was not read to the end")
    """

    def __init__(
        self,
        member: IO[bytes],
        name: str,
        file_size: int,
        expected_hash: bytes | None = None,
        hash_algorithm: str | None = None,
        expected_size: int | None = None,
        expected_crc: int | None = None,
    ):
        self._member = member
        self.name = name
        self._file_size = file_size
        self._expected_hash = expected_hash
        self._hash_algorithm = hash_algorithm
        self._expected_size = expected_size
        self._expected_crc = expected_crc
        self._digest = (
            hashlib.new(hash_algorithm) if hash_algorithm is not None else None
        )
        self._crc = 0
        self._pos = 0
        self._verified = False

    @property
    def verified(self) -> bool:
        """``True`` once the whole member has been read and every applicable
        check (RECORD digest, declared size and ZIP CRC-32) has passed."""
        return self._verified

    def _observe(self, data: bytes) -> None:
        if data:
            if self._digest is not None:
                self._digest.update(data)
            self._crc = zlib.crc32(data, self._crc)
            self._pos += len(data)

    def _reset_checksums(self) -> None:
        if self._digest is not None:
            self._digest = hashlib.new(self._hash_algorithm)
        self._crc = 0
        self._pos = 0
        self._verified = False

    def _finish(self) -> None:
        if self._verified:
            return

        if self._expected_size is not None and self._pos != self._expected_size:
            raise WheelError(
                f"Size mismatch for file '{self.name}': expected "
                f"{self._expected_size} bytes, got {self._pos}"
            )
        if self._file_size is not None and self._pos != self._file_size:
            raise WheelError(
                f"Size mismatch for file '{self.name}': archive declares "
                f"{self._file_size} bytes, got {self._pos}"
            )
        if (
            self._digest is not None
            and self._expected_hash is not None
            and self._digest.digest() != self._expected_hash
        ):
            raise WheelError(f"Hash mismatch for file '{self.name}'")
        if self._expected_crc is not None and self._crc != self._expected_crc:
            raise WheelError(f"Bad CRC-32 for file '{self.name}'")

        self._verified = True

    def _at_eof(self) -> bool:
        return self._pos >= self._file_size

    def _read1(self, size: int) -> bytes:
        try:
            data = self._member.read1(size)
        except _INTEGRITY_ERRORS as exc:
            raise WheelError(f"Failed to verify file '{self.name}': {exc}") from exc

        self._observe(data)
        if not data or self._at_eof():
            self._finish()

        return data

    def read(self, size: int | None = -1) -> bytes:
        """Read up to *size* bytes, or until EOF when *size* is negative or
        omitted."""
        self._checkClosed()
        if size == 0:
            return b""
        if size is None or size < 0:
            chunks: list[bytes] = []
            while True:
                chunk = self._read1(-1)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)

        remaining = size
        parts: list[bytes] = []
        while remaining > 0:
            chunk = self._read1(remaining)
            if not chunk:
                break
            parts.append(chunk)
            remaining -= len(chunk)
        return b"".join(parts)

    def read1(self, size: int | None = -1) -> bytes:
        """Read up to *size* bytes with at most one underlying read call."""
        self._checkClosed()
        if size == 0:
            return b""
        return self._read1(-1 if size is None else size)

    def readinto(self, buffer: SizedBuffer) -> int:
        """Read bytes into a preallocated *buffer* and return the number of
        bytes written."""
        self._checkClosed()
        if not isinstance(buffer, memoryview):
            buffer = memoryview(buffer)
        if not buffer:
            return 0
        data = self.read1(len(buffer))
        end = len(data)
        buffer[:end] = data
        return end

    def readline(self, size: int | None = -1) -> bytes:
        """Read and return a single line from the member."""
        self._checkClosed()
        if size == 0:
            return b""
        try:
            line = self._member.readline(-1 if size is None else size)
        except _INTEGRITY_ERRORS as exc:
            raise WheelError(f"Failed to verify file '{self.name}': {exc}") from exc

        self._observe(line)
        if not line or self._at_eof():
            self._finish()
        return line

    def seekable(self) -> bool:
        self._checkClosed()
        return bool(self._member.seekable())

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        """Seek within the member.

        Forward seeks consume (and hash) the skipped data.  Backward seeks
        reset the member and the checksums.  Seeking to the end reads the rest
        of the member and therefore completes verification.
        """
        self._checkClosed()
        if not self._member.seekable():
            raise io.UnsupportedOperation("underlying stream is not seekable")
        if whence == io.SEEK_SET:
            target = offset
        elif whence == io.SEEK_CUR:
            target = self._pos + offset
        elif whence == io.SEEK_END:
            target = self._file_size + offset
        else:
            raise ValueError(
                "whence must be os.SEEK_SET (0), os.SEEK_CUR (1), or os.SEEK_END (2)"
            )

        target = max(0, min(target, self._file_size))
        if target < self._pos:
            self._member.seek(0)
            self._reset_checksums()

        if target > self._pos:
            self._skip(target - self._pos)

        return self._pos

    def _skip(self, count: int) -> None:
        remaining = count
        while remaining > 0:
            chunk = self._read1(remaining)
            if not chunk:
                break
            remaining -= len(chunk)

    def tell(self) -> int:
        """Return the current logical position within the member."""
        self._checkClosed()
        return self._pos

    def close(self) -> None:
        """Close the underlying stream.

        A member closed before EOF is not verified; :attr:`verified` remains
        ``False`` and no error is raised for the unread remainder."""
        if not self.closed:
            try:
                self._member.close()
            finally:
                super().close()

    def readable(self) -> bool:
        self._checkClosed()
        return True

    def writable(self) -> bool:
        return False


class WheelFile(ZipFile):
    """A ZipFile derivative class that also reads SHA-256 hashes from
    .dist-info/RECORD and checks any read files against those.
    """

    _default_algorithm = hashlib.sha256

    def __init__(
        self,
        file: StrPath,
        mode: Literal["r", "w", "x", "a"] = "r",
        compression: int = ZIP_DEFLATED,
    ):
        basename = os.path.basename(file)
        self.parsed_filename = WHEEL_INFO_RE.match(basename)
        if not basename.endswith(".whl") or self.parsed_filename is None:
            raise WheelError(f"Bad wheel filename {basename!r}")

        ZipFile.__init__(self, file, mode, compression=compression, allowZip64=True)

        self.dist_info_path = "{}.dist-info".format(
            self.parsed_filename.group("namever")
        )
        self.record_path = self.dist_info_path + "/RECORD"
        self._file_hashes: dict[str, tuple[str | None, bytes | str | None]] = {}
        self._file_sizes: dict[str, int] = {}
        if mode == "r":
            # The .dist-info directory inside the wheel may use normalized
            # (lowercase) naming even when the filename does not. Resolve the
            # actual path case-insensitively.
            if self.record_path not in self.namelist():
                lowered = self.dist_info_path.lower() + "/record"
                for name in self.namelist():
                    if name.lower() == lowered:
                        self.dist_info_path = name.rsplit("/RECORD", 1)[0]
                        self.record_path = name
                        break

            # Ignore RECORD and any embedded wheel signatures
            self._file_hashes[self.record_path] = None, None
            self._file_hashes[self.record_path + ".jws"] = None, None
            self._file_hashes[self.record_path + ".p7s"] = None, None

            # Fill in the expected hashes by reading them from RECORD
            try:
                record = self.open(self.record_path)
            except KeyError:
                raise WheelError(f"Missing {self.record_path} file") from None

            with record:
                for line in csv.reader(
                    TextIOWrapper(record, newline="", encoding="utf-8")
                ):
                    path, hash_sum, size = line
                    if size:
                        self._file_sizes[path] = int(size)
                    if not hash_sum:
                        continue

                    algorithm, hash_sum = hash_sum.split("=")
                    try:
                        hashlib.new(algorithm)
                    except ValueError:
                        raise WheelError(
                            f"Unsupported hash algorithm: {algorithm}"
                        ) from None

                    if algorithm.lower() in {"md5", "sha1"}:
                        raise WheelError(
                            f"Weak hash algorithm ({algorithm}) is not permitted by "
                            f"PEP 427"
                        )

                    self._file_hashes[path] = (
                        algorithm,
                        urlsafe_b64decode(hash_sum.encode("ascii")),
                    )

    def open(
        self,
        name_or_info: str | ZipInfo,
        mode: Literal["r", "w"] = "r",
        pwd: bytes | None = None,
    ) -> IO[bytes]:
        ef_name = (
            name_or_info.filename if isinstance(name_or_info, ZipInfo) else name_or_info
        )
        if (
            mode == "r"
            and not ef_name.endswith("/")
            and ef_name not in self._file_hashes
        ):
            raise WheelError(f"No hash found for file '{ef_name}'")

        ef = ZipFile.open(self, name_or_info, mode, pwd)
        if mode == "r" and not ef_name.endswith("/"):
            algorithm, expected_hash = self._file_hashes[ef_name]
            info = (
                name_or_info
                if isinstance(name_or_info, ZipInfo)
                else self.getinfo(name_or_info)
            )
            if expected_hash is None:
                # RECORD itself and signature files carry no digest of their
                # own; the ZIP CRC and the declared size are still checked.
                algorithm = None

            return VerifyingReader(
                ef,
                ef_name,
                file_size=info.file_size,
                expected_hash=expected_hash,
                hash_algorithm=algorithm,
                expected_size=self._file_sizes.get(ef_name),
                expected_crc=info.CRC,
            )

        return ef

    def write_files(self, base_dir: str) -> None:
        log.info("creating %r and adding %r to it", self.filename, base_dir)
        deferred: list[tuple[str, str]] = []
        for root, dirnames, filenames in os.walk(base_dir):
            # Sort the directory names so that `os.walk` will walk them in a
            # defined order on the next iteration.
            dirnames.sort()
            for name in sorted(filenames):
                path = os.path.normpath(os.path.join(root, name))
                if os.path.isfile(path):
                    arcname = os.path.relpath(path, base_dir).replace(os.path.sep, "/")
                    if arcname == self.record_path:
                        pass
                    elif root.endswith(".dist-info"):
                        deferred.append((path, arcname))
                    else:
                        self.write(path, arcname)

        deferred.sort()
        for path, arcname in deferred:
            self.write(path, arcname)

    def write(
        self,
        filename: str,
        arcname: str | None = None,
        compress_type: int | None = None,
    ) -> None:
        with open(filename, "rb") as f:
            st = os.fstat(f.fileno())
            data = f.read()

        zinfo = ZipInfo(
            arcname or filename, date_time=get_zipinfo_datetime(st.st_mtime)
        )
        zinfo.external_attr = (stat.S_IMODE(st.st_mode) | stat.S_IFMT(st.st_mode)) << 16
        zinfo.compress_type = compress_type or self.compression
        self.writestr(zinfo, data, compress_type)

    def writestr(
        self,
        zinfo_or_arcname: str | ZipInfo,
        data: SizedBuffer | str,
        compress_type: int | None = None,
    ) -> None:
        if isinstance(zinfo_or_arcname, str):
            zinfo_or_arcname = ZipInfo(
                zinfo_or_arcname, date_time=get_zipinfo_datetime()
            )
            zinfo_or_arcname.compress_type = self.compression
            zinfo_or_arcname.external_attr = (0o664 | stat.S_IFREG) << 16

        if isinstance(data, str):
            data = data.encode("utf-8")

        ZipFile.writestr(self, zinfo_or_arcname, data, compress_type)
        fname = (
            zinfo_or_arcname.filename
            if isinstance(zinfo_or_arcname, ZipInfo)
            else zinfo_or_arcname
        )
        log.info("adding %r", fname)
        if fname != self.record_path:
            hash_ = self._default_algorithm(data)
            self._file_hashes[fname] = (
                hash_.name,
                urlsafe_b64encode(hash_.digest()).decode("ascii"),
            )
            self._file_sizes[fname] = len(data)

    def close(self) -> None:
        # Write RECORD
        if self.fp is not None and self.mode == "w" and self._file_hashes:
            data = StringIO()
            writer = csv.writer(data, delimiter=",", quotechar='"', lineterminator="\n")
            writer.writerows(
                (
                    (fname, algorithm + "=" + hash_, self._file_sizes[fname])
                    for fname, (algorithm, hash_) in self._file_hashes.items()
                )
            )
            writer.writerow((format(self.record_path), "", ""))
            self.writestr(self.record_path, data.getvalue())

        ZipFile.close(self)
