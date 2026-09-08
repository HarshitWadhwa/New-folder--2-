"""
Automated unit tests for Python Password Strength Analyzer
Run with: python3.14 test_password_analyzer.py
"""

import unittest
from password_analyzer import (
    analyze_password,
    generate_random_password,
    generate_passphrase,
    suggest_alternatives,
    save_password_with_reuse_check,
    view_password_history
)


class TestPasswordAnalyzer(unittest.TestCase):

    def test_weak_dictionary_password(self):
        result = analyze_password("password")
        self.assertEqual(result["rating"], "Very Weak")
        self.assertLessEqual(result["score"], 25)
        self.assertFalse(result["checks"]["Not in Breach Dictionary"])
        self.assertFalse(result["checks"]["Has Numbers (0-9)"])
        self.assertFalse(result["checks"]["Has Special Symbols"])

    def test_keyboard_walk_and_sequences(self):
        result = analyze_password("qwerty123")
        self.assertFalse(result["checks"]["No Keyboard Walks"])
        self.assertFalse(result["checks"]["No Sequential Runs"])

    def test_repeated_characters(self):
        result = analyze_password("aaaaaa12!A")
        self.assertFalse(result["checks"]["No Repeated Characters"])

    def test_strong_password(self):
        strong_pass = "K9#mX2$vLp8!qZ0w"
        result = analyze_password(strong_pass)
        self.assertIn(result["rating"], ["Strong", "Very Strong"])
        self.assertGreaterEqual(result["score"], 80)
        self.assertTrue(result["checks"]["Min 8 Characters"])
        self.assertTrue(result["checks"]["Has Uppercase (A-Z)"])
        self.assertTrue(result["checks"]["Has Lowercase (a-z)"])
        self.assertTrue(result["checks"]["Has Numbers (0-9)"])
        self.assertTrue(result["checks"]["Has Special Symbols"])
        self.assertGreater(result["entropy_bits"], 60)

    def test_random_generator(self):
        pwd = generate_random_password(20)
        self.assertEqual(len(pwd), 20)
        self.assertRegex(pwd, r'[a-z]')
        self.assertRegex(pwd, r'[A-Z]')
        self.assertRegex(pwd, r'[0-9]')
        self.assertRegex(pwd, r'[^a-zA-Z0-9]')

    def test_passphrase_generator(self):
        phrase = generate_passphrase(4)
        parts = phrase.split('-')
        self.assertGreaterEqual(len(parts), 4)

    def test_database_reuse_prevention(self):
        import time
        user = f"py_unit_user_{int(time.time())}"

        # 1. Initial save should succeed
        res1 = save_password_with_reuse_check(user, "InitialPass!99")
        self.assertTrue(res1["success"])
        self.assertFalse(res1["reused"])

        # 2. Reusing same password should be blocked
        res2 = save_password_with_reuse_check(user, "InitialPass!99")
        self.assertFalse(res2["success"])
        self.assertTrue(res2["reused"])
        self.assertIn("violates security policy", res2["message"])

        # 3. Setting a new password should succeed
        res3 = save_password_with_reuse_check(user, "BrandNewPass#100")
        self.assertTrue(res3["success"])
        self.assertFalse(res3["reused"])

        # 4. History log should contain 2 entries
        history = view_password_history(user)
        self.assertEqual(len(history), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
