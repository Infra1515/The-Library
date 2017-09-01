# Tests dedicated to UserModel
import unittest
import time
from app import create_app, db
from app.models import User

class UserModelTestCase(unittest.TestCase):
    def construct_app(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db_create_all()

    def deconstruct_app(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_can_set_password(self):
        u = User(password = "dinosaur")
        self.assertTrue(u.password_hash is not None)

    def test_password_is_not_reachable(self):
        u = User(password = "dinosaur")
        with self.assertRaises(AttributeError):
            u.password

    def test_password_verification(self):
        u = User(password="dinosaur")
        self.assertTrue(u.verify_password("dinosaur"))
        self.assertFalse(u.verify_password("dog"))


    def test_random_password_salts(self):
        u1 = User(password="dinosaur")
        u2 = User(password = "dinosaur")
        self.assertTrue(u1.password_hash != u2.password_hash)

    def test_valid_generation_of_confirmation_tokens(self):
        u = User(password='dinosaur')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token()
        self.assertTrue(u.confirm(token))

    def test_invalid_generation_of_confirmation_tokens(self):
        u1 = User(password='dinosaur')
        u2 = User(password='dinosaur')
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()
        token = u1.generate_confirmation_token()
        self.assertFalse(u2.confirm(token))

    def test_expired_confirmation_token(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token(1)
        time.sleep(2)
        self.assertFalse(u.confirm(token))
