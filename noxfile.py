"""
Runs tests and other routines.

Usage:
  1. Install "nox"
  2. Run "nox" or "nox -s test"
"""

import nox

SUPPORTED_PYTHON_VERSIONS = ["3.8", "3.9", "3.10", "3.11", "3.12"]

@nox.session(python=SUPPORTED_PYTHON_VERSIONS)
def test(session):
    """Run pytests"""
    session.install("-e", ".[testing]")
    session.run("pytest")


@nox.session(python=SUPPORTED_PYTHON_VERSIONS)
def build(session):
    """Build source and wheel distribution"""
    session.run("python", "setup.py", "sdist")
    session.run("python", "setup.py", "bdist_wheel")


@nox.session(python=False)
def release_patch(session):
    """Generate release patch"""
    session.run("mkdir", "-p", "dist", external=True)
    with open("./dist/updates.patch", "w") as out:
        session.run(
            "git", "format-patch", "--stdout", "master",
            external=True,
            stdout=out
        )
