"""Project configuration package.

Import the settings module rather than individual names so that a single
source of truth is obvious at the call site:

    from config import settings
    settings.DATA_RAW
"""

from . import settings

__all__ = ["settings"]
