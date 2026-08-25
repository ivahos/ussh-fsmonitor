# Security

Report vulnerabilities to security@ussh.au. Please don't open public issues
for security reports.

Design commitments this helper makes, in order of importance:

1. It never runs with more privilege than the SSH session that started it.
2. It writes to nothing but its own stdout and stderr.
3. It has no network code and opens no sockets.
4. It exits when stdin closes; it cannot outlive the session.
5. Release binaries are reproducible from the tagged source and carry a
   signed statement of their digest.
