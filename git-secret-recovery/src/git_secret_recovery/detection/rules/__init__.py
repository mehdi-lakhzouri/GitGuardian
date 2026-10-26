"""Detection rules.

Each rule is a pure function ``detect(content: bytes) -> Iterator[Hit]``. Rules work on
raw bytes so offsets are exact byte offsets and binary blobs need no decoding.
"""

from __future__ import annotations

Hit = tuple[str, int, int]  # (secret_type, start byte offset, end byte offset)
