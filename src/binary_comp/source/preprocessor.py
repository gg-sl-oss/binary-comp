"""Conditional-compilation filtering for the tree-sitter source inventory.

Tree-sitter parses every arm of a conditional.  When the arms each open a
brace -- the usual shape of code that keeps a port beside the original, e.g.

    #ifdef PORT
        else if (isalpha(key)) {
    #else
        else if (_pctype[key] & _ALPHA) {
    #endif

-- the enclosing body no longer balances and every later definition in the
file drops out of the inventory.  A project can declare the macros its
reference build defines and leaves undefined; conditionals that the
declaration decides are reduced to their active arm before parsing.

Blanking replaces bytes with spaces and keeps every line break, so line
numbers and node offsets still describe the original text.  A conditional
that depends on anything undeclared is left exactly as written, and so is
every source when no declaration is configured.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class PreprocessorConfig:
    """Macros the reference build defines (with replacement text) or omits."""

    enabled: bool = False
    defined: tuple[tuple[str, str], ...] = ()
    undefined: frozenset[str] = frozenset()


_active = PreprocessorConfig()


def configure_preprocessor(config: PreprocessorConfig) -> None:
    """Install the declaration used by every later source parse."""
    global _active
    _active = config


def active_preprocessor() -> PreprocessorConfig:
    return _active


class _Undefined:
    pass


class _Unknown:
    pass


class _FunctionLike:
    pass


UNDEFINED = _Undefined()
UNKNOWN = _Unknown()
FUNCTION_LIKE = _FunctionLike()

MAX_MACRO_DEPTH = 16

_COMMENT_OR_LITERAL_RE = re.compile(
    rb"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'",
    re.S,
)
_DIRECTIVE_START_RE = re.compile(rb"^[ \t]*#", re.M)
_DIRECTIVE_RE = re.compile(r"\s*#\s*([A-Za-z_]\w*)(.*)", re.S)
_DEFINE_RE = re.compile(r"\s*([A-Za-z_]\w*)(\()?(.*)", re.S)
_IDENTIFIER_RE = re.compile(r"\s*([A-Za-z_]\w*)")
_BLANKABLE_RE = re.compile(rb"[^\r\n]")
_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<number>0[xX][0-9A-Fa-f]+|\d+)[uUlL]*"
    r"|(?P<char>'(?:\\.|[^'\\])+')"
    r"|(?P<ident>[A-Za-z_]\w*)"
    r"|(?P<op>&&|\|\||==|!=|<=|>=|<<|>>|[-+*/%<>&^|!~?:(),])"
    r")"
)

OPENING = ("if", "ifdef", "ifndef")
CONTINUING = ("elif", "elifdef", "elifndef", "else")

BINARY_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "|": 3,
    "^": 4,
    "&": 5,
    "==": 6,
    "!=": 6,
    "<": 7,
    ">": 7,
    "<=": 7,
    ">=": 7,
    "<<": 8,
    ">>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "/": 10,
    "%": 10,
}


class _Malformed(Exception):
    pass


class _Unparsable(Exception):
    pass


@dataclass
class _Directive:
    start: int
    end: int
    keyword: str
    argument: str


@dataclass
class _Branch:
    directive: _Directive
    items: list = field(default_factory=list)
    end: int = 0


@dataclass
class _Group:
    branches: list[_Branch] = field(default_factory=list)
    endif: _Directive | None = None


def blank_inactive_conditionals(source: bytes, config: PreprocessorConfig | None = None) -> bytes:
    """Return ``source`` with every decided conditional reduced to its active arm."""
    config = _active if config is None else config
    if not config.enabled:
        return source

    directives = _scan_directives(source)
    if not directives:
        return source
    try:
        items = _build_tree(directives)
    except _Malformed:
        return source

    state: dict[str, object] = {name: value for name, value in config.defined}
    for name in config.undefined:
        state[name] = UNDEFINED
    ranges: list[tuple[int, int]] = []
    _process(items, state, True, ranges)
    if not ranges:
        return source

    blanked = bytearray(source)
    for start, end in ranges:
        blanked[start:end] = _BLANKABLE_RE.sub(b" ", bytes(blanked[start:end]))
    return bytes(blanked)


def _scan_directives(source: bytes) -> list[_Directive]:
    comments = [
        (match.start(), match.end())
        for match in _COMMENT_OR_LITERAL_RE.finditer(source)
        if source.startswith(b"/*", match.start())
    ]
    comment_starts = [start for start, _ in comments]
    directives: list[_Directive] = []

    for match in _DIRECTIVE_START_RE.finditer(source):
        start = match.start()
        index = bisect_right(comment_starts, start) - 1
        if index >= 0 and comments[index][0] < start < comments[index][1]:
            continue

        end = _logical_line_end(source, start)
        # A block comment opened on the directive line belongs to it; blank it
        # whole so no dangling half of the comment survives a blanked line.
        blank_end = end
        index = bisect_right(comment_starts, end) - 1
        while index >= 0 and comments[index][0] >= start:
            blank_end = max(blank_end, comments[index][1])
            index -= 1

        text = source[start:end].decode("latin-1")
        text = re.sub(r"\\\r?\n", " ", text)
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
        text = re.sub(r"/\*.*", " ", text, flags=re.S)
        text = re.sub(r"//.*", " ", text)
        parsed = _DIRECTIVE_RE.match(text)
        if parsed is None:
            continue
        directives.append(_Directive(start, blank_end, parsed.group(1), parsed.group(2).strip()))

    return directives


def _logical_line_end(source: bytes, start: int) -> int:
    position = start
    while True:
        newline = source.find(b"\n", position)
        if newline < 0:
            return len(source)
        line = source[position:newline].rstrip(b"\r")
        if not line.endswith(b"\\"):
            return newline
        position = newline + 1


def _build_tree(directives: list[_Directive]) -> list:
    root: list = []
    current = root
    stack: list[tuple[_Group, list]] = []

    for directive in directives:
        if directive.keyword in OPENING:
            group = _Group(branches=[_Branch(directive)])
            current.append(group)
            stack.append((group, current))
            current = group.branches[-1].items
        elif directive.keyword in CONTINUING:
            if not stack:
                raise _Malformed
            group, _ = stack[-1]
            if group.branches[-1].directive.keyword == "else":
                raise _Malformed
            group.branches[-1].end = directive.start
            group.branches.append(_Branch(directive))
            current = group.branches[-1].items
        elif directive.keyword == "endif":
            if not stack:
                raise _Malformed
            group, current = stack.pop()
            group.branches[-1].end = directive.start
            group.endif = directive
        else:
            current.append(directive)

    if stack:
        raise _Malformed
    return root


def _process(items: list, state: dict[str, object], certain: bool, ranges: list[tuple[int, int]]) -> None:
    for item in items:
        if isinstance(item, _Group):
            _process_group(item, state, certain, ranges)
        elif item.keyword == "define":
            _define(item.argument, state, certain)
        elif item.keyword == "undef":
            name = _IDENTIFIER_RE.match(item.argument)
            if name is not None:
                state[name.group(1)] = UNDEFINED if certain else UNKNOWN


def _process_group(group: _Group, state: dict[str, object], certain: bool, ranges: list[tuple[int, int]]) -> None:
    active = None
    for index, branch in enumerate(group.branches):
        taken = _branch_condition(branch.directive, state)
        if taken is None:
            # The arm the build takes is unknowable: keep every arm as written.
            for undecided in group.branches:
                _process(undecided.items, state, False, ranges)
            return
        if taken:
            active = index
            break

    assert group.endif is not None
    for index, branch in enumerate(group.branches):
        ranges.append((branch.directive.start, branch.directive.end))
        if index == active:
            _process(branch.items, state, certain, ranges)
        else:
            ranges.append((branch.directive.end, branch.end))
    ranges.append((group.endif.start, group.endif.end))


def _define(argument: str, state: dict[str, object], certain: bool) -> None:
    parsed = _DEFINE_RE.match(argument)
    if parsed is None:
        return
    name = parsed.group(1)
    if not certain:
        state[name] = UNKNOWN
    elif parsed.group(2):
        state[name] = FUNCTION_LIKE
    else:
        state[name] = parsed.group(3).strip()


def _branch_condition(directive: _Directive, state: dict[str, object]) -> bool | None:
    keyword = directive.keyword
    if keyword == "else":
        return True
    if keyword in ("ifdef", "ifndef", "elifdef", "elifndef"):
        name = _IDENTIFIER_RE.match(directive.argument)
        if name is None:
            return None
        defined = _is_defined(state, name.group(1))
        if defined is None:
            return None
        return defined if keyword in ("ifdef", "elifdef") else not defined
    value = evaluate_condition(directive.argument, state)
    return None if value is None else value != 0


def _is_defined(state: dict[str, object], name: str) -> bool | None:
    value = state.get(name, UNKNOWN)
    if value is UNKNOWN:
        return None
    return value is not UNDEFINED


def evaluate_condition(expression: str, state: dict[str, object], depth: int = 0) -> int | None:
    """Evaluate an ``#if`` expression; ``None`` when it depends on the unknown."""
    try:
        tokens = _tokenize(expression)
        parser = _ExpressionParser(tokens, state, depth)
        value = parser.conditional()
        if parser.position != len(tokens):
            raise _Unparsable
        return value
    except _Unparsable:
        return None


def evaluate_constant(expression: str, constants: Mapping[str, int]) -> int:
    """Evaluate a C integer constant expression with C semantics.

    Division truncates toward zero, ``010`` is octal, and character
    literals, ``%``, ``^``, ``~``, comparisons and ``?:`` are understood.
    Names resolve through ``constants``. Raises ValueError when the
    expression uses anything else or does not evaluate (division by zero).
    """
    state: dict[str, object] = {name: str(value) for name, value in constants.items()}
    value = evaluate_condition(expression, state)
    if value is None:
        raise ValueError(f"not a constant expression: {expression!r}")
    return value


def _tokenize(expression: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(expression):
        if expression[position:].strip() == "":
            break
        match = _TOKEN_RE.match(expression, position)
        if match is None or match.end() == position:
            raise _Unparsable
        kind = match.lastgroup or ""
        tokens.append((kind, match.group(kind)))
        position = match.end()
    return tokens


def _number(text: str) -> int:
    if text[:2] in ("0x", "0X"):
        return int(text, 16)
    if len(text) > 1 and text.startswith("0"):
        try:
            return int(text, 8)
        except ValueError as exc:
            raise _Unparsable from exc
    return int(text)


def _character(text: str) -> int:
    body = text[1:-1]
    if len(body) == 1:
        return ord(body)
    escapes = {"\\n": 10, "\\t": 9, "\\r": 13, "\\0": 0, "\\\\": 92, "\\'": 39, '\\"': 34}
    if body in escapes:
        return escapes[body]
    raise _Unparsable


class _ExpressionParser:
    def __init__(self, tokens: list[tuple[str, str]], state: dict[str, object], depth: int):
        self.tokens = tokens
        self.state = state
        self.depth = depth
        self.position = 0

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self) -> tuple[str, str]:
        token = self.peek()
        if token is None:
            raise _Unparsable
        self.position += 1
        return token

    def expect(self, operator: str) -> None:
        if self.take() != ("op", operator):
            raise _Unparsable

    def conditional(self) -> int | None:
        condition = self.binary(1)
        if self.peek() != ("op", "?"):
            return condition
        self.take()
        when_true = self.conditional()
        self.expect(":")
        when_false = self.conditional()
        if condition is None:
            return when_true if when_true is not None and when_true == when_false else None
        return when_true if condition else when_false

    def binary(self, minimum: int) -> int | None:
        left = self.unary()
        while True:
            token = self.peek()
            if token is None or token[0] != "op":
                return left
            precedence = BINARY_PRECEDENCE.get(token[1])
            if precedence is None or precedence < minimum:
                return left
            self.take()
            right = self.binary(precedence + 1)
            left = _apply(token[1], left, right)

    def unary(self) -> int | None:
        token = self.peek()
        if token is not None and token[0] == "op" and token[1] in ("!", "~", "-", "+"):
            self.take()
            value = self.unary()
            if value is None:
                return None
            if token[1] == "!":
                return int(value == 0)
            if token[1] == "~":
                return ~value
            return -value if token[1] == "-" else value
        return self.primary()

    def primary(self) -> int | None:
        kind, text = self.take()
        if kind == "number":
            return _number(text)
        if kind == "char":
            return _character(text)
        if (kind, text) == ("op", "("):
            value = self.conditional()
            self.expect(")")
            return value
        if kind != "ident":
            raise _Unparsable
        if text == "defined":
            return self.defined()
        if self.peek() == ("op", "("):
            self.skip_arguments()
            return None
        return self.macro(text)

    def defined(self) -> int | None:
        parenthesized = self.peek() == ("op", "(")
        if parenthesized:
            self.take()
        kind, name = self.take()
        if kind != "ident":
            raise _Unparsable
        if parenthesized:
            self.expect(")")
        defined = _is_defined(self.state, name)
        return None if defined is None else int(defined)

    def skip_arguments(self) -> None:
        depth = 0
        while True:
            token = self.take()
            if token == ("op", "("):
                depth += 1
            elif token == ("op", ")"):
                depth -= 1
                if depth == 0:
                    return

    def macro(self, name: str) -> int | None:
        value = self.state.get(name, UNKNOWN)
        if value is UNDEFINED:
            return 0
        if not isinstance(value, str) or not value or self.depth >= MAX_MACRO_DEPTH:
            return None
        return evaluate_condition(value, self.state, self.depth + 1)


def _apply(operator: str, left: int | None, right: int | None) -> int | None:
    if operator == "||":
        if (left is not None and left != 0) or (right is not None and right != 0):
            return 1
        return None if left is None or right is None else 0
    if operator == "&&":
        if left == 0 or right == 0:
            return 0
        return None if left is None or right is None else 1
    if left is None or right is None:
        return None
    if operator in ("/", "%"):
        if right == 0:
            return None
        quotient = abs(left) // abs(right)
        if (left < 0) != (right < 0):
            quotient = -quotient
        return quotient if operator == "/" else left - quotient * right
    if operator == "<<":
        return left << right if 0 <= right < 64 else None
    if operator == ">>":
        return left >> right if 0 <= right < 64 else None
    return {
        "|": lambda: left | right,
        "^": lambda: left ^ right,
        "&": lambda: left & right,
        "==": lambda: int(left == right),
        "!=": lambda: int(left != right),
        "<": lambda: int(left < right),
        ">": lambda: int(left > right),
        "<=": lambda: int(left <= right),
        ">=": lambda: int(left >= right),
        "+": lambda: left + right,
        "-": lambda: left - right,
        "*": lambda: left * right,
    }[operator]()
