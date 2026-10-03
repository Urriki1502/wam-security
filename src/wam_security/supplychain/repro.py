"""Deterministic tar.gz builder used as the V5 reference packager."""

from __future__ import annotations

import gzip
from io import BytesIO
from pathlib import Path, PurePosixPath
import stat
import tarfile


def _mode_for(path: Path) -> int:
    mode = path.stat().st_mode
    if path.is_dir():
        return 0o755
    return 0o755 if (mode & stat.S_IXUSR) else 0o644


def build_reproducible_tar_gz(
    source_dir: str | Path,
    output: str | Path,
    *,
    root_name: str,
    source_date_epoch: int,
) -> None:
    source = Path(source_dir)
    if not source.is_dir():
        raise ValueError("source_dir must be a directory")
    if source_date_epoch < 0:
        raise ValueError("source_date_epoch must be non-negative")

    members = [source] + sorted(source.rglob("*"), key=lambda p: p.relative_to(source).as_posix())
    tar_bytes = BytesIO()

    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for path in members:
            rel = path.relative_to(source)
            arc = PurePosixPath(root_name) if rel.as_posix() == "." else PurePosixPath(root_name) / rel.as_posix()

            info = tarfile.TarInfo(arc.as_posix())
            info.mtime = source_date_epoch
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mode = _mode_for(path)

            if path.is_dir():
                info.type = tarfile.DIRTYPE
                info.size = 0
                tf.addfile(info)
            elif path.is_symlink():
                info.type = tarfile.SYMTYPE
                info.linkname = path.readlink().as_posix()
                info.size = 0
                tf.addfile(info)
            elif path.is_file():
                data = path.read_bytes()
                info.type = tarfile.REGTYPE
                info.size = len(data)
                tf.addfile(info, BytesIO(data))
            else:
                raise ValueError(f"unsupported filesystem entry: {path}")

    raw = tar_bytes.getvalue()
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as f:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=f,
            mtime=source_date_epoch,
            compresslevel=9,
        ) as gz:
            gz.write(raw)
