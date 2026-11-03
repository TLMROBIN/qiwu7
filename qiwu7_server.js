#!/usr/bin/env node
// Keep one authorization implementation. The legacy token server is retired.
const {spawn} = require('child_process');
const path = require('path');
const child = spawn(process.env.PYTHON || 'python3', [path.join(__dirname, 'qiwu7_server.py'), ...process.argv.slice(2)], {stdio:'inherit',env:process.env});
child.on('error', () => {console.error('Python 3 is required for the authenticated server.');process.exit(1);});
child.on('exit', code => process.exit(code || 0));
for (const signal of ['SIGINT','SIGTERM']) process.on(signal, () => child.kill(signal));
