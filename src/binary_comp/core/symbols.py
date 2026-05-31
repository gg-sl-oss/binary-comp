"""Symbol name normalization and matching."""

from __future__ import annotations

import re


def split_name_parameters(name: str) -> str:
    return name.split("(", 1)[0]


def decode_msvc_pointer_class_tokens(encoded: str) -> list[str]:
    """Class names of the ``PAV<class>@@`` pointer tokens in a mangled tail.

    Numeric back-references (``PAV2@@``) repeat the previous token.
    """
    tokens: list[str] = []
    for match in re.finditer(r"PAV([^@]+)@@", encoded):
        token = match.group(1)
        if token.isdigit():
            if tokens:
                tokens.append(tokens[-1])
            continue
        tokens.append(token.replace("@", "::"))
    return tokens


def normalize_compiled(name: str, signature_names: frozenset[str] = frozenset()) -> str:
    """Demangle a rebuilt MSVC symbol to a readable ``Class::method`` form.

    For names listed in ``signature_names`` (overloaded methods), the decoded
    pointer-parameter types are appended, e.g.
    ``?PopSafe@TimedEventPool@@QAEPAVSpriteAction@@PAV2@@Z`` ->
    ``TimedEventPool::PopSafe(SpriteAction*)``.
    """
    name = name.strip()
    if name.startswith("??0") and "@@" in name:
        match = re.match(r"\?\?0(\w+)@@", name)
        if match:
            return f"{match.group(1)}::{match.group(1)}"
    if name.startswith("??1") and "@@" in name:
        match = re.match(r"\?\?1(\w+)@@", name)
        if match:
            return f"{match.group(1)}::~{match.group(1)}"
    if name.startswith("??2@"):
        return "operator_new"
    if name.startswith("??3@"):
        return "operator_delete"
    if name.startswith("?") and "@@" in name:
        match = re.match(r"\?(\w+)@(\w+)@@", name)
        if match:
            normalized = f"{match.group(2)}::{match.group(1)}"
            if normalized in signature_names:
                class_tokens = decode_msvc_pointer_class_tokens(name[match.end():])
                if len(class_tokens) > 1:
                    return f"{normalized}({','.join(f'{item}*' for item in class_tokens[1:])})"
            return normalized
        match = re.match(r"\?(\w+)@@", name)
        if match:
            return match.group(1)
    if name.startswith("_") and "::" not in name and "@" not in name:
        return name[1:]
    match = re.match(r"@([\w]+)@\d+", name)
    if match:
        return match.group(1)
    match = re.match(r"_?(\w+)@\d+$", name)
    if match:
        return match.group(1)
    if "eh vector constructor iterator" in name:
        return "__eh_vec_ctor__"
    if "eh vector destructor iterator" in name:
        return "__eh_vec_dtor__"
    return name


def canonical_function_name(name: str) -> str:
    return split_name_parameters(name)


def symbol_patterns_for_function(name: str) -> list[str]:
    base = split_name_parameters(name)
    if "::" in base:
        class_name, method_name = base.rsplit("::", 1)
        class_leaf = class_name.rsplit("::", 1)[-1]
        if method_name == class_leaf:
            return [f"??0{class_leaf}@@"]
        if method_name.startswith("~"):
            return [f"??1{class_leaf}@@"]
        return [f"?{method_name}@{class_leaf}@@"]
    return [f"?{base}@@", f"_{base}@", f"_{base}"]


def symbol_matches(mangled: str, patterns: list[str]) -> bool:
    return any(pattern == mangled or mangled.startswith(pattern) or pattern in mangled for pattern in patterns)
