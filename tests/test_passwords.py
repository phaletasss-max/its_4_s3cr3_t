import string
import unittest

from secret_tools.errors import ToolError
from secret_tools.passwords import analyze_password, generate_password


class PasswordToolsTests(unittest.TestCase):
    def test_generator_uses_requested_length_and_categories(self) -> None:
        password = generate_password(40)

        self.assertEqual(len(password), 40)
        self.assertTrue(any(character.islower() for character in password))
        self.assertTrue(any(character.isupper() for character in password))
        self.assertTrue(any(character.isdigit() for character in password))
        self.assertTrue(any(character not in string.ascii_letters + string.digits for character in password))

    def test_generator_can_omit_symbols(self) -> None:
        password = generate_password(20, include_symbols=False)
        self.assertTrue(password.isalnum())

    def test_generator_rejects_unsafe_lengths(self) -> None:
        for length in (0, 11, 257):
            with self.subTest(length=length), self.assertRaises(ToolError):
                generate_password(length)

    def test_zxcvbn_distinguishes_weak_and_strong_passwords(self) -> None:
        weak = analyze_password("password123")
        strong = analyze_password("correct horse battery staple extra violet")

        self.assertLess(weak.score, strong.score)
        self.assertEqual(strong.label, "muy fuerte")


if __name__ == "__main__":
    unittest.main()

