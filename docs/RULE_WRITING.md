# Rule writing guide

1. Create a class extending `Rule` in `commandcompass/rules/`.
2. Define `metadata` with stable ID `CC-...`.
3. Implement `evaluate(parser_result, request)` returning list of `Finding`.
4. Add to `default_rules()` in `commandcompass/rules/__init__.py`.
5. Add unit tests in `tests/rules/`.
6. Ensure evidence is specific and redacted by core.
