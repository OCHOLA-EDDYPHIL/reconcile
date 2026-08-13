import unittest

from reconcile.cli import build_parser, main


class CliTests(unittest.TestCase):
    def test_parser_uses_reconcile_program_name(self) -> None:
        self.assertEqual(build_parser().prog, "reconcile")

    def test_empty_invocation_succeeds(self) -> None:
        self.assertEqual(main([]), 0)


if __name__ == "__main__":
    unittest.main()
