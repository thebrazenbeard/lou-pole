"""Python code signals must come from executable tokens, not prose."""

import unittest

from freerowcochkar import analyze


class PythonCodeLiteralTests(unittest.TestCase):
    def test_python_docstrings_comments_and_strings_do_not_trigger_code_findings(self):
        source = '''
def explain():
    """A documentation example:
    except Exception:
        pass
    fail_open
    """
    # except Exception: pass
    # default_allow
    return "except ValueError: return True"
'''
        report = analyze(source, profile="code")
        self.assertEqual(
            [],
            [finding.rule_id for finding in report.findings if finding.rule_id.startswith("FRC-CODE-")],
        )

    def test_real_python_swallow_and_fail_open_survive_literal_filtering(self):
        source = '''
def authorize():
    """This text says except Exception: pass and fail_open."""
    try:
        return check_policy()
    except Exception:
        pass

def second_path():
    # except ValueError: return True
    try:
        return check_policy()
    except ValueError:
        return True
'''
        report = analyze(source, profile="code")
        code_ids = [finding.rule_id for finding in report.findings if finding.rule_id.startswith("FRC-CODE-")]
        self.assertEqual(["FRC-CODE-001", "FRC-CODE-002"], code_ids)
        self.assertEqual([6, 13], [finding.evidence[0].line_start for finding in report.findings if finding.rule_id.startswith("FRC-CODE-")])

    def test_non_python_code_still_uses_generic_signal_detection(self):
        report = analyze("const default_allow = true;", profile="code")
        self.assertIn("FRC-CODE-002", {finding.rule_id for finding in report.findings})

    def test_f_string_literal_prose_is_not_executable_code(self):
        source = '''
def explain(name):
    return f"""Example only:
    except Exception:
        pass {name}
    fail_open
    """
'''
        report = analyze(source, profile="code")
        self.assertEqual(
            [],
            [finding.rule_id for finding in report.findings if finding.rule_id.startswith("FRC-CODE-")],
        )

    def test_executable_python_broad_except_and_f_string_expression_stay_visible(self):
        source = '''
def process():
    example = f"{default_allow()}"
    try:
        return check_policy()
    except Exception as error:
        raise error
'''
        report = analyze(source, profile="code")
        code_ids = {finding.rule_id for finding in report.findings if finding.rule_id.startswith("FRC-CODE-")}
        self.assertEqual({"FRC-CODE-002", "FRC-CODE-003"}, code_ids)


if __name__ == "__main__":
    unittest.main()
