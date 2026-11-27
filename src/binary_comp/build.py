"""Run a target's configured clean and build commands."""

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Sequence

from binary_comp.config import ProjectTarget
from binary_comp.core.mapfile import clear_map_cache


class BuildError(RuntimeError):
    pass


def maybe_build(target: ProjectTarget, do_build: bool, extra_args: Sequence[str] = ()) -> None:
    """Run the target's clean command, then its build command.

    Does nothing when ``do_build`` is false. Commands are split like a POSIX
    shell would split them, so quoted arguments survive, but no shell runs.
    ``extra_args`` and the configured job count are appended to the build
    command. The build's own output goes to the terminal so its errors are
    visible; a failing clean or build raises ``BuildError``.
    """
    if not do_build:
        return
    try:
        _run_clean_and_build(target, extra_args)
    finally:
        # The build may have relinked maps that were already read this run.
        clear_map_cache()


def _run_clean_and_build(target: ProjectTarget, extra_args: Sequence[str]) -> None:
    if target.build.clean:
        clean_command = split_command(target.build.clean, "clean")
        result = subprocess.run(
            clean_command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            check=False,
        )
        if result.returncode != 0:
            raise BuildError(command_failure("clean", clean_command, result.returncode, result.stderr))
    if not target.build.build:
        return
    build_command = split_command(target.build.build, "build")
    build_command.extend(extra_args)
    if target.build.jobs and target.build.jobs > 1:
        build_command.append(f"-j{target.build.jobs}")
    result = subprocess.run(build_command, check=False)
    if result.returncode != 0:
        raise BuildError(command_failure("build", build_command, result.returncode))


def split_command(command: str, label: str) -> list[str]:
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        raise BuildError(f"cannot parse {label} command {command!r}: {exc}") from exc
    if not parts:
        raise BuildError(f"{label} command is empty")
    return parts


def command_failure(label: str, command: list[str], returncode: int, stderr: str = "") -> str:
    message = f"{label} failed with exit code {returncode}: {shlex.join(command)}"
    detail = stderr.strip()
    if detail:
        message += "\n" + "\n".join(detail.splitlines()[-10:])
    return message
