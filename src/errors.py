"""Exceptions raised deliberately by the ETL pipeline.

Two levels, because the person reading the traceback cares about which one fired:

* `SchemaError` - the file is not what we think it is (missing column, unreadable
  encoding, no timestamp format matched). Nothing downstream can be trusted.
* `ValidationError` - the file parsed, but a business rule failed: unknown attack
  label, almost no parseable timestamps, every row removed.

Catching `PipelineError` therefore catches "this run is meaningless" without
also swallowing unrelated programming errors.
"""

from __future__ import annotations


class PipelineError(Exception):
    """Base class for every failure the pipeline raises on purpose."""


class SchemaError(PipelineError):
    """A capture file does not match the expected CICIDS2017 schema."""


class ValidationError(PipelineError):
    """The data parsed but broke a business rule, so the run cannot continue."""
