"""A custom rule that checks for forbidden INTEGER foreign keys.

This uses the rules API supported from 0.4.0 onwards.
"""

from sqlfluff.core.rules import (
    BaseRule,
    LintResult,
    RuleContext,
)
from sqlfluff.core.rules.crawlers import SegmentSeekerCrawler
from sqlfluff.utils.functional import FunctionalContext, sp


# These two decorators allow plugins
# to be displayed in the sqlfluff docs
class Rule_LL01(BaseRule):
    """INTEGER ... REFERENCES is forbidden! Use BIGINT instead.

    **Anti-pattern**

    Using ``INTEGER ... REFERENCES`` in a foreign key definition is creating
    a mismatch between the actual data type of the referenced primary key and
    the foreign key. See ``scripts/gen_sqlc_docker.sh`` for a long-form
    explanation.

    .. code-block:: sql

        transfer_id INTEGER NOT NULL REFERENCES asset_transfers (id),

    **Best practice**

    If the primary key of the referenced table is of type
    ``INTEGER PRIMARY KEY``, it will be transformed to ``BIGSERIAL`` in
    PostgreSQL. Therefore, the foreign key should also be of type ``BIGINT``.
    For SQLite both INTEGER and BIGINT are equivalent, so this rule is for
    PostgreSQL.

    .. code-block:: sql

        transfer_id BIGINT NOT NULL REFERENCES asset_transfers (id),
    """

    groups = ("all",)
    crawl_behaviour = SegmentSeekerCrawler({"column_definition"})
    is_fix_compatible = True

    def __init__(self, *args, **kwargs):
        """Overwrite __init__ to set config."""
        super().__init__(*args, **kwargs)

    def _eval(self, context: RuleContext):
        """We should not use INTEGER ... REFERENCES."""
        has_integer = False
        has_reference = False
        data_type_segment = None

        for child in context.segment.segments:
            if child.type == "data_type":
                # Check if any part of data_type is INTEGER.
                for part in child.segments:
                    if part.raw.upper() == "INTEGER":
                        has_integer = True
                        data_type_segment = part
            elif child.type == "column_constraint_segment":
                # Look for REFERENCES keyword inside constraints.
                for subpart in child.segments:
                    if "REFERENCES" in subpart.raw.upper():
                        has_reference = True

        if has_integer and has_reference:
            return LintResult(
                anchor=data_type_segment,
                description="Must use BIGINT instead of INTEGER as a data "
                            "type in foreign key references. See "
                            "scripts/gen_sqlc_docker.sh for explanation.",
            )

        return None
