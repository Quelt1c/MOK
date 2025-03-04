import unittest
from mok2 import ShiftCipher, TrithemiusCipher  

class TestShiftCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = ShiftCipher()

    def test_encrypt_decrypt_english(self):
        text = "hello world"
        key = 3
        alphabet = self.cipher.latin_alphabet

        encrypted = self.cipher.encrypt(text, key, alphabet)
        decrypted = self.cipher.decrypt(encrypted, key, alphabet)

        self.assertEqual(decrypted, text)

    def test_encrypt_decrypt_ukrainian(self):
        text = "привіт світ"
        key = 5
        alphabet = self.cipher.ukrainian_alphabet

        encrypted = self.cipher.encrypt(text, key, alphabet)
        decrypted = self.cipher.decrypt(encrypted, key, alphabet)

        self.assertEqual(decrypted, text)

    def test_brute_force_attack(self):
        text = "hello world"
        key = 7
        alphabet = self.cipher.latin_alphabet

        encrypted = self.cipher.encrypt(text, key, alphabet)
        results = self.cipher.brute_force_attack(encrypted, alphabet)

        found = False
        for k, plaintext in results:
            if plaintext == text:
                found = True
                break

        self.assertTrue(found)

    def test_frequency_analysis(self):
        text = "hello world"
        alphabet = self.cipher.latin_alphabet

        freq = self.cipher.frequency_analysis(text, alphabet)

        self.assertAlmostEqual(freq['l'], 0.3, places=1)
        self.assertAlmostEqual(freq['o'], 0.2, places=1)


class TestTrithemiusCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = TrithemiusCipher()

    def test_encrypt_decrypt_linear_key_english(self):
        text = "hello world"
        key = (1, 2)  # Linear key: k = 1*p + 2
        alphabet = self.cipher.latin_alphabet

        encrypted = self.cipher.encrypt(text, key, alphabet)
        decrypted = self.cipher.decrypt(encrypted, key, alphabet)

        self.assertEqual(decrypted, text)

    def test_encrypt_decrypt_quadratic_key_ukrainian(self):
        text = "привіт світ"
        key = (1, 2, 3)  # Quadratic key: k = 1*p^2 + 2*p + 3
        alphabet = self.cipher.ukrainian_alphabet

        encrypted = self.cipher.encrypt(text, key, alphabet)
        decrypted = self.cipher.decrypt(encrypted, key, alphabet)

        self.assertEqual(decrypted, text)

    def test_encrypt_decrypt_keyword_english(self):
        text = "hello world"
        key = "key"  # Keyword key
        alphabet = self.cipher.latin_alphabet

        encrypted = self.cipher.encrypt(text, key, alphabet)
        decrypted = self.cipher.decrypt(encrypted, key, alphabet)

        self.assertEqual(decrypted, text)



if __name__ == "__main__":
    unittest.main()