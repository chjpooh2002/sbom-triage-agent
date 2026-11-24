"""Lexical boundaries for the JS/Java patterns inspected by C4."""
import bisect
import re


_TOKEN = re.compile(
    r"""//[^\n]*|/\*[\s\S]*?(?:\*/|$)|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"""
    r"|`(?:\\.|[^`\\])*`|[\w$]+|=>|===|==|!=|\+=|-=|\?\.|[^\s]"
)


class Tokens:
    def __init__(self, text: str):
        starts = [m.end() for m in re.finditer("\n", text)]
        self.words = []
        self.lines = []
        self.pairs = {}
        stack = []
        closing = {")": "(", "}": "{", "]": "["}
        for m in _TOKEN.finditer(text):
            word = m[0]
            if word.startswith(("//", "/*")):
                continue
            i = len(self.words)
            self.words.append(word)
            self.lines.append(1 + bisect.bisect_right(starts, m.start()))
            if word in {"(", "{", "["}:
                stack.append(i)
            elif word in closing and stack and self.words[stack[-1]] == closing[word]:
                start = stack.pop()
                self.pairs[start] = i
                self.pairs[i] = start

    def at(self, index):
        return self.words[index] if 0 <= index < len(self.words) else ""

    def quoted(self, index):
        return self.at(index).startswith(('"', "'"))
