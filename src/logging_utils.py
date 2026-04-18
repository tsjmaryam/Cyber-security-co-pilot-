from __future__ import annotations

import logging
import os


DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


def configure_logging(level: str | None = None) -> None:
    resolved_level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        logging.basicConfig(level=resolved_level, format=DEFAULT_LOG_FORMAT)
        return
    root_logger.setLevel(resolved_level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
