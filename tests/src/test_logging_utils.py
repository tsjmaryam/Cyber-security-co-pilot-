from __future__ import annotations

import logging

from src.logging_utils import DEFAULT_LOG_FORMAT, configure_logging, get_logger


def test_configure_logging_updates_existing_root_level():
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_level = root.level
    try:
        if not root.handlers:
            root.addHandler(logging.StreamHandler())
        root.setLevel(logging.WARNING)
        configure_logging("debug")
        assert root.level == logging.DEBUG
    finally:
        root.handlers = original_handlers
        root.setLevel(original_level)


def test_get_logger_returns_named_logger():
    logger = get_logger("cyber.test")
    assert logger.name == "cyber.test"
    assert DEFAULT_LOG_FORMAT.endswith("%(message)s")
