"""Checks the built distribution files for the gate and the release.

    python -I -B check_wheel.py files --dist DIR --licence FILE --changelog FILE [--version V]
    python -I -B check_wheel.py import
    python -I -B check_wheel.py spell TAG

``files`` inspects one wheel and one source archive: no declared requirement,
the licence the repository holds, the version given or else that of the
newest dated section of the changelog, in the wheel and in the source
archive's name, and exactly the module's own files in both.
``import`` runs under an interpreter the wheel was installed for and imports
the client from there. ``spell`` prints a release tag's version as Python
spells it.
"""

from __future__ import annotations

import argparse
import email.parser
import email.policy
import gzip
import importlib
import posixpath
import re
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = tomllib.loads((HERE / "pyproject.toml").read_text(encoding="utf-8"))
MODULE = PROJECT["tool"]["flit"]["module"]["name"]

_DATED = re.compile(r"^## \[([^\]]+)\] - \d{4}-\d{2}-\d{2}$", re.MULTILINE)
_RELEASE = re.compile(r"^(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)(?:\.(\d+))?)?$")
_PREVIEW = {"alpha": "a", "beta": "b", "rc": "rc"}
# What a wheel's own directory holds; an entry point or a script would be more.
_DESCRIBED = {"METADATA", "WHEEL", "RECORD", "licenses/LICENSE"}
# What a source archive holds beside src/.
_ARCHIVED = {"LICENSE", "README.md", "pyproject.toml", "PKG-INFO"}
_VERSION_LINE = re.compile(r'^version = "[^"]*"$', re.MULTILINE)


def spelled(version: str) -> str:
    """A release's version, such as 1.2.3-rc.1, as a Python version spells it."""
    parts = _RELEASE.fullmatch(version)
    if parts is None:
        raise SystemExit(f"check_wheel: {version} is no version this check can map")
    base, kind, number = parts.groups()
    return base if kind is None else f"{base}{_PREVIEW[kind]}{number or 0}"


def release_version(changelog: str) -> str:
    """The newest dated section's version, as a Python version spells it."""
    sections = _DATED.findall(changelog)
    if not sections:
        raise SystemExit("check_wheel: the changelog has no dated section")
    return spelled(sections[0])


def tag_version(tag: str) -> str:
    """A release tag's version, as a Python version spells it."""
    if not tag.startswith("v"):
        raise SystemExit(f"check_wheel: {tag} is no release tag")
    return spelled(tag[1:])


def _one(directory: Path, pattern: str) -> Path:
    found = sorted(directory.glob(pattern))
    if len(found) != 1:
        raise SystemExit(f"check_wheel: want one {pattern} in {directory}, found {len(found)}")
    return found[0]


def _own_files() -> set[str]:
    src = HERE / "src"
    return {p.relative_to(src).as_posix() for p in (src / MODULE).rglob("*") if p.is_file()}


def check_files(
    dist: Path, licence: Path, changelog: Path, version: str | None = None
) -> list[str]:
    problems: list[str] = []
    want = version or release_version(changelog.read_text(encoding="utf-8"))
    name = PROJECT["project"]["name"].replace("-", "_")
    info = f"{name}-{want}.dist-info"

    with zipfile.ZipFile(_one(dist, "*.whl")) as wheel:
        names = set(wheel.namelist())
        if f"{info}/METADATA" not in names:
            return [f"the wheel holds no {info}/METADATA: its version is not {want}"]
        problems += _metadata_problems("the wheel", wheel.read(f"{info}/METADATA"), want)
        if f"{info}/licenses/LICENSE" not in names:
            problems.append("the wheel carries no licence")
        elif wheel.read(f"{info}/licenses/LICENSE") != licence.read_bytes():
            problems.append("the wheel's licence is not the repository's")
        held = {n for n in names if not n.startswith(info + "/")}
        if held != _own_files():
            problems.append(f"the wheel's files differ from src/: {sorted(held ^ _own_files())}")
        changed = sorted(
            n for n in held & _own_files() if wheel.read(n) != (HERE / "src" / n).read_bytes()
        )
        if changed:
            problems.append(f"the wheel's files do not hold what src/ holds: {changed}")
        described = {n.removeprefix(info + "/") for n in names if n.startswith(info + "/")}
        if described != _DESCRIBED:
            problems.append(f"the wheel describes itself with other files: {sorted(described)}")

    problems += _archive_problems(dist, f"{name}-{want}", want, licence.read_bytes())
    if (HERE / "LICENSE").read_bytes() != licence.read_bytes():
        problems.append("clients/python/LICENSE is not the repository's LICENSE")
    return problems


def _archive_problems(dist: Path, stem: str, want: str, licence: bytes) -> list[str]:
    archive = _one(dist, "*.tar.gz")
    problems = (
        []
        if archive.name == f"{stem}.tar.gz"
        else [f"the source archive is not named {stem}.tar.gz"]
    )
    with tarfile.open(archive) as sdist:
        files, found = _archive_files(sdist, stem)
        end = sdist.offset
    # tarfile stops at a header it cannot read, where another extractor skips
    # on to the files behind it.
    try:
        with gzip.open(archive) as raw:
            raw.seek(end)
            if raw.read().strip(b"\0"):
                found.append("the source archive holds bytes after its last file")
    except OSError as exc:
        found.append(f"the source archive is no gzip stream: {exc}")
    problems += found
    if any(n.startswith("tests/") for n in files):
        problems.append("the source archive carries the tests")
    if "LICENSE" not in files:
        problems.append("the source archive carries no licence")
    own = {"src/" + n for n in _own_files()} | _ARCHIVED
    if set(files) != own:
        problems.append(
            f"the source archive's files differ from the project's: {sorted(set(files) ^ own)}"
        )
    expected = {n: (HERE / n).read_bytes() for n in own - {"LICENSE", "PKG-INFO"}}
    expected["LICENSE"] = licence
    expected["pyproject.toml"] = _project_as(want)
    changed = sorted(n for n in set(files) & set(expected) if files[n] != expected[n])
    if changed:
        problems.append(f"the source archive's files do not hold what the project holds: {changed}")
    problems += _metadata_problems("the source archive", files.get("PKG-INFO", b""), want)
    return problems


def _metadata_problems(what: str, metadata: bytes, want: str) -> list[str]:
    """Read as installers read it: header names without case, the first of a repeated one."""
    headers = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(
        metadata, headersonly=True
    )
    problems = []
    if headers.get_all("Version") != [want]:
        problems.append(f"{what}'s version is not {want}: {headers.get_all('Version')}")
    if headers.get_all("Name") != [PROJECT["project"]["name"]]:
        problems.append(f"{what} names another project: {headers.get_all('Name')}")
    required = headers.get_all("Requires-Dist")
    if required:
        problems.append(f"{what} declares a requirement: {required[0]}")
    return problems


def _archive_files(archive: tarfile.TarFile, stem: str) -> tuple[dict[str, bytes], list[str]]:
    """The regular files under stem/ by their plain names, and what else the archive holds."""
    files: dict[str, bytes] = {}
    problems: set[str] = set()
    names: list[str] = []
    for entry in archive.getmembers():
        top, _, name = entry.name.partition("/")
        if top != stem or not name:
            problems.add(f"the source archive's files are not all under {stem}/")
            continue
        names.append(name)
        if not _plain(name):
            problems.add(f"the source archive names a path that is not plain: {entry.name}")
        elif not entry.isfile():
            problems.add("the source archive holds a link, a directory or a special file")
        else:
            files[name] = _read(archive, entry)
    if len({n.casefold() for n in names}) != len(names):
        problems.add("the source archive names a file twice")
    return files, sorted(problems)


def _plain(name: str) -> bool:
    segments = name.split("/")
    return (
        name == posixpath.normpath(name)
        and "\\" not in name
        and all(s not in ("", ".", "..") for s in segments)
    )


def _project_as(version: str) -> bytes:
    """The project file as a build under that version writes it."""
    text = (HERE / "pyproject.toml").read_text(encoding="utf-8")
    return _VERSION_LINE.sub(f'version = "{version}"', text, count=1).encode("utf-8")


def _read(archive: tarfile.TarFile, entry: tarfile.TarInfo) -> bytes:
    data = archive.extractfile(entry)
    return data.read() if data is not None else b""


def check_import() -> list[str]:
    module = importlib.import_module(f"{MODULE}.enforce")
    origin = Path(module.__file__ or "").resolve()
    if HERE in origin.parents:
        return [f"{MODULE}.enforce was imported from the tree, not from the wheel: {origin}"]
    if not hasattr(module, "Client"):
        return [f"the installed {MODULE}.enforce holds no Client"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    files = commands.add_parser("files")
    files.add_argument("--dist", type=Path, required=True)
    files.add_argument("--licence", type=Path, required=True)
    files.add_argument("--changelog", type=Path, required=True)
    files.add_argument("--version", help="the version the files carry instead of the changelog's")
    commands.add_parser("import")
    spell = commands.add_parser("spell")
    spell.add_argument("tag")
    args = parser.parse_args()

    if args.command == "spell":
        print(tag_version(args.tag))
        return 0
    if args.command == "files":
        problems = check_files(args.dist, args.licence, args.changelog, args.version)
    else:
        problems = check_import()
    for problem in problems:
        print(f"check_wheel: {problem}", file=sys.stderr)
    if not problems:
        print(f"check_wheel: {args.command} ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
