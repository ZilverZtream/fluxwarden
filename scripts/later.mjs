// Answers an unavailable npm capability with one fixed stderr line and exit 1.
process.stderr.write('fluxwarden: this capability is not yet available\n');
process.exitCode = 1;
