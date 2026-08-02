# Contributing

Contributions are welcome. Please keep the project dependency-free at runtime,
avoid deployment-specific assumptions, and preserve the panel's security
boundaries.

Before opening a pull request:

1. Keep configuration and credentials out of commits.
2. Run `python -m py_compile garage_panel.py`.
3. Run `python -m build` and install the resulting wheel in a clean virtual
   environment when packaging code changes.
4. If you change the embedded dashboard JavaScript, extract it and run
   `node --check` before submitting.
5. Update the README and changelog when a user-facing behavior changes.

For changes that affect destructive operations, authentication, secret
handling, or integration commands, describe the threat model and test evidence
in the pull request.
