#!/usr/bin/env node
// Runs the installed `tearmesh mcp connect` with stdio passed straight through. No dependencies.
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const win = process.platform === 'win32';
const name = win ? 'tearmesh.exe' : 'tearmesh';
// The setting arrives as an argument (Desktop drops mcp_config.env); an unset one may be empty or left as the template.
const setting = (process.argv[2] || '').trim();
const given = setting && !setting.startsWith('${') ? setting : '';

function find() {
  if (given) return fs.existsSync(given) ? given : null;
  const dirs = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  // Desktop may have started before install added the PATH entry, so also try where install puts it.
  if (win) dirs.push(path.join(process.env.ProgramFiles || 'C:\\Program Files', 'tearmesh'));
  for (const d of dirs) {
    const p = path.join(d, name);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function fail(msg) {
  process.stderr.write(msg + '\n');
  process.exit(1);
}

const exe = find();
if (!exe) {
  fail(given
    ? `tear-mesh was not found at ${given}: fix the path in this extension's settings, or clear it.`
    : "tear-mesh was not found: install tear-mesh on this PC, or set the path to tearmesh.exe in this extension's settings.");
}
const child = spawn(exe, ['mcp', 'connect'], { stdio: 'inherit' });
child.on('error', (e) => fail(`tear-mesh could not be started (${e.message}): install tear-mesh, or set the path to tearmesh.exe in this extension's settings.`));
child.on('exit', (code) => process.exit(code === null ? 1 : code));
