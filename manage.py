#!/usr/bin/env python
"""
This is a shell executable file that can control the application.
Created with flask-script .
more info: https://flask-script.readthedocs.io/en/latest/.
Main functions : $./manage.py runserver -p 5xxx - runs the application
$./manage.py db upgrade; $./manage.py db migrate - migrates the DB
$./manage.py shell - Creates a shell session with the app imported
$./manage.py tests - Runs the tests in the test folder
"""

import os
from app import create_app, db
from app.models import User, Role
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

app = create_app(os.getenv("THE_LIBRARY_CONFIG") or 'default')
manager = Manager(app)
migrate = Migrate(app,db)

def make_shell_context():
    """ Used for creating a shell session of the app
    by default returns a dict returning the application instance
    Used for Shell() which takes it as argument
    """
    return dict(app=app, db=db, User=User, Role=Role)
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)

@manager.command
def test():
    """ Function to call the unit tests."""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)

if __name__ == '__main__':
    manager.run()
