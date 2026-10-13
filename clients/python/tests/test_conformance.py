"""The client cases of the shared files: the client, a second client, and that one broken."""

from __future__ import annotations

import unittest
from collections.abc import Callable
from datetime import datetime

from guardana_control.enforce import Client
from tests import harness
from tests.second_client import DEFECTS
from tests.second_client import SecondClient as Second


def method_name(case_id: str) -> str:
    return "test_" + case_id.replace("-", "_")


def reference(socket: str, token: str, clock: Callable[[], datetime]) -> harness.Caller:
    return Client(socket, token, 5.0, clock=clock)


def second(defect: str = "") -> harness.Maker:
    def make(socket: str, token: str, clock: Callable[[], datetime]) -> harness.Caller:
        return Second(socket, token, 5.0, clock=clock, defect=defect)

    return make


class ReferenceClient(unittest.TestCase):
    """The client passes every client case."""


class SecondClient(unittest.TestCase):
    """A client written apart from the first passes every case with no defect."""


class NegativeControls(unittest.TestCase):
    """The second client, told to break a case's rule, fails that case."""


def _passes(make: harness.Maker, case_id: str) -> Callable[[unittest.TestCase], None]:
    def test(self: unittest.TestCase) -> None:
        self.assertEqual(harness.run_case(make, case_id), [])

    return test


def _fails(case: dict[str, object]) -> Callable[[unittest.TestCase], None]:
    control = harness.as_object(case["negative_control"], "negative_control")
    defect = harness.as_text(control["defect"], "defect")

    def test(self: unittest.TestCase) -> None:
        self.assertIn(defect, DEFECTS)
        misses = harness.run_case(second(defect), harness.as_text(case["id"], "id"))
        self.assertNotEqual(misses, [], f"a client that {control['breaks']} passed")

    return test


for _case in harness.client_cases():
    _id = harness.as_text(_case["id"], "id")
    setattr(ReferenceClient, method_name(_id), _passes(reference, _id))
    setattr(SecondClient, method_name(_id), _passes(second(), _id))
    setattr(NegativeControls, method_name(_id), _fails(_case))


class CaseFiles(unittest.TestCase):
    """The index, the directories and the defects name one another."""

    def test_the_index_lists_the_directories(self) -> None:
        listed = sorted(harness.as_text(case["id"], "id") for case in harness.client_cases())
        held = sorted(entry.name for entry in (harness.TESTDATA / "client").iterdir())
        self.assertEqual(listed, held)
        self.assertEqual(len(listed), 17)

    def test_every_case_names_a_rule_and_a_defect_the_second_client_has(self) -> None:
        for case in harness.client_cases():
            control = harness.as_object(case["negative_control"], "negative_control")
            self.assertEqual(case["contract"], "v1alpha1")
            self.assertTrue(case["rule"] and control["breaks"], case["id"])
            self.assertIn(control["defect"], DEFECTS, case["id"])

    def test_the_second_client_has_no_defect_without_a_case(self) -> None:
        used = {
            harness.as_object(case["negative_control"], "negative_control")["defect"]
            for case in harness.client_cases()
        }
        self.assertEqual(used, set(DEFECTS))
        self.assertEqual(len(DEFECTS), 16)
