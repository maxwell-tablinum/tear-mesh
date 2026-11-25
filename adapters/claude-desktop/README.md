# tear-mesh for Claude Desktop

A Claude Desktop extension (`tearmesh.mcpb`, Windows only) that gives Claude the tools of your tear-mesh hub.
It holds no copy of tear-mesh: it runs the installed `tearmesh mcp connect`, which starts your hub if needed.

Before you install it:
1. tear-mesh is installed on this PC with your own Windows user in a boundary: `tearmesh install ... --me BOUNDARY`.
2. This machine has joined a mesh.

Install: open Claude Desktop, Settings, Extensions, Advanced settings, Install Extension, pick `tearmesh.mcpb`
(or drag the file into the window). Restart Claude Desktop if it was open during tear-mesh's install.

It works when the extension shows as running and Claude lists tear-mesh tools (ask it to list your mesh's machines).

If it fails, the extension's log says one of:
- "tear-mesh was not found: install tear-mesh ...": tear-mesh is missing or not on PATH. Install it, or set the path to `tearmesh.exe` in the extension's settings (normally `C:\Program Files\tearmesh\tearmesh.exe`).
- "tear-mesh was not found at ...": the path in the settings is wrong.
- "tear-mesh could not be started": the file is there but will not run; reinstall tear-mesh.

Build the file: `adapters/claude-desktop/pack.sh OUT.mcpb` (needs Node; the version must match Cargo.toml).
