"""Tiny HTML builder: every string is escaped unless it is already a Node.

Pre-rendered pages show upstream-influenced text. Building markup by
concatenating values is how injection happens, so nothing here accepts a raw
HTML string; text is escaped, attribute values are escaped and quoted.
"""

from __future__ import annotations

import html
from collections.abc import Iterable
from typing import Union

VOID = frozenset({"br", "hr", "img", "input", "link", "meta"})


class Node:
    __slots__ = ("tag", "attrs", "children")

    def __init__(self, tag: str, attrs: dict[str, object] | None, children: list["Child"]):
        self.tag = tag
        self.attrs = attrs or {}
        self.children = children

    def html(self) -> str:
        parts = [f"<{self.tag}"]
        for key, value in self.attrs.items():
            if value is None or value is False:
                continue
            if value is True:
                parts.append(f" {key}")
            else:
                # Attributes are always double-quoted, so a single quote needs no escape.
                escaped = html.escape(str(value), quote=True).replace("&#x27;", "'")
                parts.append(f' {key}="{escaped}"')
        parts.append(">")
        if self.tag in VOID:
            return "".join(parts)
        parts.extend(render(child) for child in self.children)
        parts.append(f"</{self.tag}>")
        return "".join(parts)


class Text:
    """Escaped text node."""

    __slots__ = ("value",)

    def __init__(self, value: object):
        self.value = "" if value is None else str(value)

    def html(self) -> str:
        return html.escape(self.value, quote=False)


Child = Union[Node, Text, str, None, Iterable]


def render(child: Child) -> str:
    if child is None:
        return ""
    if hasattr(child, "html"):
        return child.html()
    if isinstance(child, str):
        return html.escape(child, quote=False)
    return "".join(render(item) for item in child)


def el(tag: str, attrs: dict[str, object] | None = None, *children: Child) -> Node:
    return Node(tag, attrs, list(children))


def fragment(*children: Child) -> str:
    return "".join(render(child) for child in children)
