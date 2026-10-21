"""The decision's version rule of both clients, held to the table the Go readers read."""

from __future__ import annotations

import json
import unittest

from guardana_control.enforce import _ops
from tests import harness
from tests.second_client import _version_read

TABLE = harness.TESTDATA.parent / "contracts" / "schema_versions.json"


class DecisionVersions(unittest.TestCase):
    """A decision is read on major 1 only, with a minor in 32 bits."""

    def rows(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = json.loads(TABLE.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(rows), 10)
        return rows

    def test_the_client_reads_the_table(self) -> None:
        for row in self.rows():
            with self.subTest(version=row["version"]):
                answer = {"decision": {"schemaVersion": row["version"]}}
                self.assertEqual(_ops._readable_decision(answer), row["admitted"])

    def test_the_second_client_reads_the_table(self) -> None:
        for row in self.rows():
            with self.subTest(version=row["version"]):
                self.assertEqual(_version_read({"schemaVersion": row["version"]}), row["admitted"])

    def test_an_answer_with_no_decision_is_left_to_its_outcome(self) -> None:
        self.assertTrue(_ops._readable_decision({"outcome": "OUTCOME_BLOCK"}))
        self.assertTrue(_version_read(None))
        self.assertFalse(_ops._readable_decision({"decision": {}}))
        self.assertFalse(_version_read({}))
