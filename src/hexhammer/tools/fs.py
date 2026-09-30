"""文件系统工具:read / write / edit / grep / find / ls。"""

from __future__ import annotations

import re
from typing import ClassVar

from .base import ToolContext, ToolError, resolve_in_workspace

_MAX_GREP_RESULTS = 200


class ReadTool:
    name = "read"
    description = "Read a text file. Returns numbered lines. Use offset/limit for large files."
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "offset": {"type": "integer", "description": "1-based start line"},
            "limit": {"type": "integer", "description": "max lines to return"},
        },
        "required": ["path"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        path = resolve_in_workspace(ctx, args["path"])
        if not path.is_file():
            raise ToolError(f"not a file: {args['path']}")
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        offset = max(1, int(args.get("offset", 1)))
        limit = int(args.get("limit", len(lines)))
        window = lines[offset - 1 : offset - 1 + limit]
        if not window and lines:
            raise ToolError(f"offset {offset} beyond file ({len(lines)} lines)")
        return "\n".join(f"{i + offset:6}\t{line}" for i, line in enumerate(window))


class WriteTool:
    name = "write"
    description = "Create or overwrite a file with the given content."
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
        },
        "required": ["path", "content"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        path = resolve_in_workspace(ctx, args["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(args["content"], encoding="utf-8")
        return f"wrote {len(args['content'])} chars to {args['path']}"


class EditTool:
    name = "edit"
    description = (
        "Replace an exact string in a file. old_string must be unique unless "
        "replace_all is true."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "old_string": {"type": "string"},
            "new_string": {"type": "string"},
            "replace_all": {"type": "boolean"},
        },
        "required": ["path", "old_string", "new_string"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        path = resolve_in_workspace(ctx, args["path"])
        if not path.is_file():
            raise ToolError(f"not a file: {args['path']}")
        text = path.read_text(encoding="utf-8", errors="replace")
        old, new = args["old_string"], args["new_string"]
        count = text.count(old)
        if count == 0:
            raise ToolError("old_string not found")
        if count > 1 and not args.get("replace_all"):
            raise ToolError(f"old_string appears {count} times; pass replace_all=true")
        replaced = text.replace(old, new) if args.get("replace_all") else text.replace(old, new, 1)
        path.write_text(replaced, encoding="utf-8")
        return f"replaced {count if args.get('replace_all') else 1} occurrence(s)"


class GrepTool:
    name = "grep"
    description = "Regex search across files under a path. Returns path:line:text matches."
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string"},
            "path": {"type": "string", "description": "file or directory, default workspace root"},
        },
        "required": ["pattern"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        pattern = re.compile(args["pattern"])
        root = resolve_in_workspace(ctx, args.get("path", "."))
        matches: list[str] = []
        files = [root] if root.is_file() else sorted(root.rglob("*"))
        for file in files:
            if not file.is_file() or file.is_symlink():
                continue
            try:
                text = file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    rel = file.relative_to(ctx.workspace)
                    matches.append(f"{rel}:{lineno}:{line.strip()}")
                    if len(matches) >= _MAX_GREP_RESULTS:
                        matches.append(f"... capped at {_MAX_GREP_RESULTS} matches")
                        return "\n".join(matches)
        return "\n".join(matches) if matches else "no matches"


class FindTool:
    name = "find"
    description = "Glob-pattern file search, e.g. '**/*.py'. Returns paths relative to workspace."
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string"},
            "path": {"type": "string", "description": "search root, default workspace root"},
        },
        "required": ["pattern"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        root = resolve_in_workspace(ctx, args.get("path", "."))
        hits = sorted(
            p.relative_to(ctx.workspace)
            for p in root.glob(args["pattern"])
            if p.is_file()
        )
        return "\n".join(str(h) for h in hits) if hits else "no files found"


class LsTool:
    name = "ls"
    description = "List a directory. Directories get a trailing '/'."
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": [],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        path = resolve_in_workspace(ctx, args.get("path", "."))
        if not path.is_dir():
            raise ToolError(f"not a directory: {args.get('path', '.')}")
        entries = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name))
        out = [f"{e.name}{'/' if e.is_dir() else ''}" for e in entries]
        return "\n".join(out) if out else "(empty)"


def default_fs_tools() -> list:
    return [ReadTool(), WriteTool(), EditTool(), GrepTool(), FindTool(), LsTool()]
