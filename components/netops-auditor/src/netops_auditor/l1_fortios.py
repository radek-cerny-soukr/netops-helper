from __future__ import annotations

import re
from dataclasses import dataclass, field

_UNESCAPED_QUOTE = re.compile(r'(?<!\\)"')


class ParseError(Exception):
    pass


@dataclass(frozen=True)
class Attr:
    values: tuple
    line: int
    unset: bool = False

    def value(self) -> str:
        return " ".join(self.values)


@dataclass
class Node:
    path: tuple
    line: int
    attrs: dict = field(default_factory=dict)
    sub: dict = field(default_factory=dict)
    entries: dict = field(default_factory=dict)

    def value(self, name, default=None):
        attr = self.attrs.get(name)
        if attr is None or attr.unset:
            return default
        return attr.value()

    def values(self, name) -> tuple:
        attr = self.attrs.get(name)
        if attr is None or attr.unset:
            return ()
        return attr.values

    def line_of(self, name):
        attr = self.attrs.get(name)
        return None if attr is None else attr.line

    def section(self, name):
        return self.sub.get(name)


def tokenize(text: str) -> list:
    tokens, current, in_quotes, escaped, quoted = [], "", False, False, False
    for char in text:
        if escaped:
            current += char
            escaped = False
        elif char == "\\" and in_quotes:
            escaped = True
        elif char == '"':
            in_quotes = not in_quotes
            quoted = True
        elif char in " \t" and not in_quotes:
            if current or quoted:
                tokens.append(current)
                current, quoted = "", False
        else:
            current += char
    if current or quoted:
        tokens.append(current)
    return tokens


def logical_lines(text: str):
    buffer, start = None, 0
    for number, line in enumerate(text.splitlines(), 1):
        if buffer is None:
            buffer, start = line, number
        else:
            buffer += "\n" + line
        if len(_UNESCAPED_QUOTE.findall(buffer)) % 2 == 0:
            yield start, buffer
            buffer = None
    if buffer is not None:
        raise ParseError("unterminated quoted value opened at line %d" % start)


def parse(text: str) -> Node:
    root = Node(path=(), line=0)
    stack = [root]
    for number, raw in logical_lines(text):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = tokenize(line)
        if not tokens:
            continue
        command = tokens[0]
        if command == "config":
            name = " ".join(tokens[1:])
            node = stack[-1].sub.get(name)
            if node is None:
                node = Node(path=stack[-1].path + (name,), line=number)
                stack[-1].sub[name] = node
            stack.append(node)
        elif command == "edit":
            key = tokens[1] if len(tokens) > 1 else ""
            node = stack[-1].entries.get(key)
            if node is None:
                node = Node(path=stack[-1].path + (key,), line=number)
                stack[-1].entries[key] = node
            stack.append(node)
        elif command == "set":
            if len(tokens) < 2:
                raise ParseError("line %d: set without an attribute" % number)
            stack[-1].attrs[tokens[1]] = Attr(values=tuple(tokens[2:]), line=number)
        elif command == "unset":
            if len(tokens) < 2:
                raise ParseError("line %d: unset without an attribute" % number)
            stack[-1].attrs[tokens[1]] = Attr(values=(), line=number, unset=True)
        elif command in ("next", "end"):
            if len(stack) == 1:
                raise ParseError("line %d: %s outside of a block" % (number, command))
            stack.pop()
    if len(stack) != 1:
        raise ParseError("unterminated block opened at line %d" % stack[-1].line)
    return root
