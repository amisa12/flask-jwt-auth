# project/server/tests/test_config.py


import unittest

from flask import current_app
from flask_testing import TestCase

from app import app


class TestDevelopmentConfig(TestCase):
    def create_app(self):
        app.config.from_object('app.config.DevelopmentConfig')
        return app

    def test_app_is_development(self):
        self.assertFalse(app.config['SECRET_KEY'] is '\xdc`\xdc1V]\xf4\xc1c\xea\xb7\xaa\xbcz\x9b\xaa!\xef5}\x0e\xd3\xc2\x04')
        self.assertTrue(app.config['DEBUG'] is True)
        self.assertFalse(current_app is None)
        self.assertTrue(
            app.config['SQLALCHEMY_DATABASE_URI'] == 'postgresql://postgres:@localhost/lending_v2'
        )

    class TestTestingConfig(TestCase):
        def create_app(self):
            app.config.from_object('app.config.TestingConfig')
            return app

        def test_app_is_testing(self):
            self.assertFalse(app.config['SECRET_KEY'] is '\xdc`\xdc1V]\xf4\xc1c\xea\xb7\xaa\xbcz\x9b\xaa!\xef5}\x0e\xd3\xc2\x04')
            self.assertTrue(app.config['DEBUG'])
            self.assertTrue(
                app.config['SQLALCHEMY_DATABASE_URI'] == 'postgresql://postgres:@localhost/lending_v2_test'
            )

class TestProductionConfig(TestCase):
    def create_app(self):
        app.config.from_object('app.config.ProductionConfig')
        return app

    def test_app_is_production(self):
        self.assertTrue(app.config['DEBUG'] is False)


if __name__ == '__main__':
    unittest.main()
