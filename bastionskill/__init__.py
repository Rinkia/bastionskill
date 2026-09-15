"""bastionskill — static scanner for skill-poisoning (code-layer).

Point it at an agent skill (a SKILL.md plus its bundled scripts). It inspects the
bundled executable code for malicious behavior — network egress, obfuscated exec,
secret reads, destructive commands, and persistence/hook install — and reports the
*shadow*: what the code does that SKILL.md never declared.

Prompt-layer risks (malicious SKILL.md instructions, hidden unicode) are delegated
to bastionsupply; this tool owns the code-layer.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .models import Finding, ScanReport, Skill, SourceFile
from .scanner import scan

__all__ = ["Finding", "ScanReport", "Skill", "SourceFile", "scan", "__version__"]
