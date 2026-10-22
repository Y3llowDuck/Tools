"""AI reasoning engine.

Ties the assessment loop together:
    Discover → Understand → Hypothesize → Test → Observe → Adapt → Validate → Chain → Report

The model reasons and decides *what capability to request next*; Python
enforces scope, selects a plugin, executes the tool, parses output, and
persists results. The model never sees or runs a command.
"""
