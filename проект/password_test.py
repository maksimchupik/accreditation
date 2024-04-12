# python password_test.py -v
import unittest
from password import Password


#Test cases to test Calulator methods
#You always create  a child class derived from unittest.TestCase
class TestPassword(unittest.TestCase):
  #setUp method is overridden from the parent class TestCase
  def setUp(self):
    self.password = Password()

  def test_validate_by_regexp(self):
    self.assertEqual(self.password.validate_by_regexp("qWer5ty"),
                     "Password has incorrecr format.")

  def test_validate_by_common_list(self):
    self.assertEqual(self.password.validate_by_common_list("qWer5%ty"),
                     "Do not use so common password.")

  def test_validate_by_similarity(self):
    user_login = 'joda777jedi'
    email = 'jedimaster1@jediacademy.co'
    self.assertEqual(
        self.password.validate_by_similarity("jedimaster1", user_login, email),
        "Password is too similar on other user field.")

  def test_decrypt_password(self, cipher, encrypted_password):
        return cipher.decrypt(encrypted_password.encode()).decode()

  def test_initialize_cipher(self, key):
        return Fernet(key)

if __name__ == "__main__":
  unittest.main()
