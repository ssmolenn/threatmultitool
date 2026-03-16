import os
from pathlib import Path

_rules = None
_rules_error = None


def _load_rules():
    global _rules, _rules_error
    rules_dir = Path(__file__).parent.parent / "yara_rules"
    rule_files = list(rules_dir.glob("*.yar"))
    if not rule_files:
        _rules_error = "No YARA rule files found"
        return

    try:
        import yara
        filepaths = {f.stem: str(f) for f in rule_files}
        _rules = yara.compile(filepaths=filepaths)
    except ImportError:
        _rules_error = "yara-python not installed"
    except Exception as e:
        _rules_error = f"Failed to compile YARA rules: {e}"


def scan(data: bytes) -> dict:
    global _rules, _rules_error

    if _rules is None and _rules_error is None:
        _load_rules()

    if _rules_error:
        return {"error": _rules_error, "matches": []}

    if _rules is None:
        return {"error": "Rules not loaded", "matches": []}

    try:
        import yara
        matches = _rules.match(data=data, timeout=30)
        return {
            "matches": [
                {
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags),
                    "meta": dict(m.meta),
                    "strings": [
                        {"offset": s.instances[0].offset if s.instances else 0, "identifier": s.identifier}
                        for s in m.strings[:5]
                    ],
                }
                for m in matches
            ]
        }
    except Exception as e:
        return {"error": str(e), "matches": []}
