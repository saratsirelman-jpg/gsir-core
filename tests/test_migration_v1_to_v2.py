import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from migrations.migrate_v1_to_v2 import migrate_v1_to_v2


def test_migrate_v1_to_v2():
    v1 = {
        "task_type": "x",
        "schema_version": "1.0.0",
        "inputs": {"a": 1},
        "normalized": True
    }

    v2 = migrate_v1_to_v2(v1)

    assert v2["migration_level"] == 2
    assert v2["task_type"] == "x"
    assert v2["schema_version"] == "1.0.0"
    assert v2["inputs"] == {"a": 1}
    assert v2["normalized"] is True