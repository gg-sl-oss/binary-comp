"""Records shared by the original and rebuilt vtable checks."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ClassMethod:
    """A method declared in a class body in a header."""

    class_name: str
    method_name: str
    # Name plus normalised parameter types; ``__dtor__`` for a destructor.
    signature_key: str
    is_virtual: bool
    # An explicit ``slot N`` note next to the declaration, if any.
    slot_index: int | None
    display_name: str
    file: str
    line_number: int


@dataclass(frozen=True)
class SourceSymbol:
    """A class method that a ``Function start`` marker places at an address."""

    class_name: str
    method_name: str
    file: str
    line_number: int

    @property
    def label(self) -> str:
        return f"{self.class_name}::{self.method_name}"


@dataclass(frozen=True)
class ClassInfo:
    """A class whose original vtable is known."""

    vtable_addr: int
    parent: str | None = None
    header: str = "(unknown)"
    constructor: int | None = None
