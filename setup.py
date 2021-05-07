from setuptools import setup, find_packages
import os


def get_version():
    """Read version from package init file (__init__.py)"""
    full_path = os.path.join((os.path.dirname((__file__))), 'okta_jwt_verifier', '__init__.py')
    with open(full_path) as f:
        for line in f:
            if '__version__' in line:
                return line.split('=')[1].strip().strip("'")


setup(
    name="okta_jwt_verifier",
    version=get_version(),
    author="Okta, Inc.",
    author_email="devex@okta.com",
    url="https://github.com/okta/okta-jwt-verifier-python",
    license="Apache License 2.0",
    description="Okta JWT Verifier",
    long_description=open("LONG_DESCRIPTION.md").read(),
    test_suite="tests",
    packages=find_packages(exclude=("tests",)),
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    install_requires=[
        "acachecontrol",
        "aiohttp",
        "python-jose",
        "retry"
    ]
)
