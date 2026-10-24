"""The rules of a call that no case file holds: building a client, and what the module exports."""

from __future__ import annotations

import math
import unittest

from guardana_control import enforce
from guardana_control.enforce import (
    BadResult,
    CallAborted,
    CallBlocked,
    CallerGone,
    CallPending,
    CallRefused,
    Client,
    EnforceError,
    MalformedAnswer,
    NoAnswer,
    NotRecorded,
    NotSent,
    Status,
    ToolRaised,
)


class Construction(unittest.TestCase):
    """A client needs a socket, a token and a finite positive timeout."""

    def test_an_empty_or_missing_socket_or_token_is_refused(self) -> None:
        for socket, token in (
            ("", "t"),
            ("s", ""),
            (None, "t"),
            ("s", None),
            (b"s", "t"),
            ("s", b"t"),
        ):
            with self.subTest(socket=socket, token=token), self.assertRaises(ValueError):
                Client(socket, token, 1.0)  # type: ignore[arg-type]

    def test_a_timeout_that_is_no_finite_positive_number_is_refused(self) -> None:
        for timeout in (
            None,
            True,
            False,
            0,
            0.0,
            -1,
            -0.5,
            math.nan,
            math.inf,
            -math.inf,
            "1",
            10**400,
        ):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(ValueError, "timeout"):
                Client("s", "t", timeout)  # type: ignore[arg-type]

    def test_the_smallest_timeouts_are_taken(self) -> None:
        for timeout in (1, 0.5, 1e-9, 5e-324):
            with self.subTest(timeout=timeout):
                self.assertIsInstance(Client("s", "t", timeout), Client)

    def test_a_token_a_header_cannot_carry_is_refused(self) -> None:
        for token in (
            "a\nb",
            "a\rb",
            "a\r\nInjected: 1",
            "a\x00b",
            "za\u017c\u00f3\u0142\u0107",
            "a\x7fb",
            "\ttab",
        ):
            with self.subTest(token=token), self.assertRaisesRegex(ValueError, "run token"):
                Client("s", token, 1.0)
        self.assertIsInstance(Client("s", "run-1.A b~!", 1.0), Client)

    def test_the_module_exports_the_interface_and_nothing_else(self) -> None:
        names = [
            "Answer",
            "BadResult",
            "CONTRACT",
            "CallAborted",
            "CallBlocked",
            "CallPending",
            "CallRefused",
            "CallerGone",
            "Client",
            "EnforceError",
            "Held",
            "MalformedAnswer",
            "NoAnswer",
            "NotRecorded",
            "NotSent",
            "Result",
            "Status",
            "ToolRaised",
        ]
        self.assertEqual(sorted(enforce.__all__), names)
        self.assertEqual(sorted(n for n in vars(enforce) if not n.startswith("_")), names)
        self.assertEqual(enforce.CONTRACT, "v1alpha1")
        self.assertEqual(
            {n: v for n, v in vars(Status).items() if not n.startswith("_")},
            {
                "SUCCESS": "COMPLETION_STATUS_SUCCESS",
                "FAILURE": "COMPLETION_STATUS_FAILURE",
                "TIMEOUT": "COMPLETION_STATUS_TIMEOUT",
                "CANCELLED": "COMPLETION_STATUS_CANCELLED",
                "UNKNOWN": "COMPLETION_STATUS_UNKNOWN",
            },
        )
        raised: tuple[type[Exception], ...] = (
            CallerGone,
            CallBlocked,
            CallPending,
            CallRefused,
            MalformedAnswer,
            CallAborted,
            NotRecorded,
            NoAnswer,
            BadResult,
            ToolRaised,
        )
        for error in raised:
            self.assertTrue(issubclass(error, EnforceError), error)
            self.assertEqual(issubclass(error, TypeError), error is BadResult, error)
        self.assertFalse(issubclass(NotSent, EnforceError))
