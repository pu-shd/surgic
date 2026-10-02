"""Split text into overlapping chunks on natural boundaries."""
from __future__ import annotations


def chunks(text: str, size: int, overlap: int) -> list[tuple[int, str]]:
    if size <= 0:
        raise ValueError("size must be positive")
    overlap = min(overlap, size // 2)
    out: list[tuple[int, str]] = []
    pos, n = 0, len(text)
    while pos < n:
        end = min(pos + size, n)
        if end < n:
            for sep in ("\n\n", "\n", ". ", " "):
                cut = text.rfind(sep, pos + size // 2, end)
                if cut != -1:
                    end = cut + len(sep)
                    break
        out.append((pos, text[pos:end]))
        if end >= n:
            break
        nxt = end - overlap
        # Never start mid-word inside the overlap.
        sp = text.find(" ", nxt, end)
        pos = sp + 1 if sp != -1 else nxt
        pos = max(pos, out[-1][0] + 1)
    return out
