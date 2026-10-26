import contextlib
import io
import unittest
from unittest.mock import patch

from ipcheck.cli import main
from ipcheck.core.models import Report
from ipcheck.core.runner import Options, run_checks
from ipcheck.output.progress import TerminalProgress, fit


class ProgressTests(unittest.TestCase):
    def test_reputation_and_assessment_are_counted_after_parallel_tasks(self):
        events = []
        activity = []
        names = ("check_network", "check_direct_ip", "check_local_ipv6", "check_dns",
                 "check_proxy", "check_timezone", "check_claude", "check_claude_routes",
                 "check_cloudflare", "check_claude_reputation", "compare_timezone")
        with contextlib.ExitStack() as stack:
            for name in names:
                stack.enter_context(patch("ipcheck.core.runner." + name, return_value=[]))
            run_checks(Options(), lambda done, total: events.append((done, total)),
                       activity=activity.append)
        self.assertEqual(events, [(done, 12) for done in range(13)])
        self.assertIn(("reputation",), activity)
        self.assertIn(("assessment",), activity)
        self.assertEqual(activity[-1], ())

    def test_display_cleans_up_on_interrupt(self):
        stream = io.StringIO()
        with self.assertRaises(KeyboardInterrupt):
            with TerminalProgress(True, stream) as display:
                display.update(2, 10)
                display.set_active(("reputation",))
                display.draw()
                raise KeyboardInterrupt
        self.assertIn("IP 类型与信誉", stream.getvalue())
        self.assertTrue(stream.getvalue().endswith("\r\x1b[2K\x1b[1A\r\x1b[2K"))
        self.assertFalse(display.thread.is_alive())

    def test_disabled_display_has_no_output(self):
        stream = io.StringIO()
        with TerminalProgress(False, stream) as display:
            display.update(1, 1)
        self.assertEqual(stream.getvalue(), "")

    def test_pipe_and_json_do_not_start_animation(self):
        for args, tty in (([], False), (["--json"], True)):
            with self.subTest(args=args):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                        patch.object(out, "isatty", return_value=tty), \
                        patch.object(err, "isatty", return_value=tty), \
                        patch("ipcheck.cli.run_checks", return_value=Report([])), \
                        patch("ipcheck.output.progress.TerminalProgress.animate") as animate:
                    main(args)
                animate.assert_not_called()
                self.assertNotIn("\x1b", err.getvalue())
                self.assertNotIn("检测中", out.getvalue())

    def test_cjk_text_fits_terminal_columns(self):
        self.assertEqual(fit("检测abc", 5), "检测a")
