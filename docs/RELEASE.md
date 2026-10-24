# Release process

1. Update version in `pyproject.toml` and `__init__.py`.
2. Update CHANGELOG.md.
3. Run tests and lint.
4. Build wheel: `python -m pip wheel . --no-deps --no-build-isolation`.
5. Tag release.
