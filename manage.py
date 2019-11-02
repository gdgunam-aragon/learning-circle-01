#!/usr/bin/env python

# THIS MODULE IS TO MANAGE ALL THE APP WITH A SIMPLE COMMANDS

import os
import click

from app import create_app, db
from app.models import User, Role, Permission
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

# CREATE AND INITIALIZE THE FLASK EXTENSION'S
app = create_app(os.getenv('FLASK_CONFIG') or 'default')  # INITIALIZE AN INSTANCE OF THE APP PASSING IT THE CONFIG
migrate = Migrate(app, db)


@app.shell_context_processor
def make_shell_context():  # THIS IS TO USE A SHELL TO INTERACT WITH THE APP
    return dict(db=db, User=User, Role=Role, Permission=Permission)


@app.cli.command()  # A DECORATOR TO EASY COMMAND CREATION
@click.argument('test_names', nargs=-1)
def test(test_names):
    """Run the unit tests."""
    import unittest
    if test_names:
        tests = unittest.TestLoader().loadTestsFromNames(test_names)
    else:
        tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)

