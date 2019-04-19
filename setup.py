#!/usr/bin/env python3

"""The setup script."""

from setuptools import setup, find_packages

version = '0.2.0'

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

with open('requirements.txt') as requirements_file:
    requirements = requirements_file.read().splitlines()

setup_requirements = ['pytest-runner', ]
test_requirements = ['pytest', ]

setup(
    name="ip-liberator",
    version=version,
    author="Wagner Macedo",
    author_email="wagnerluis1982@gmail.com",
    description="A command line utility to update AWS Security Groups rules.",
    long_description=readme + '\n\n' + history,
    py_modules = ['ip_liberator'],
    entry_points={
        'console_scripts': [
            'ip-liberator = ip_liberator.__main__:main'
        ],
    },
    install_requires=requirements,
    setup_requires=setup_requirements,
    include_package_data=True,
    packages=find_packages(include=['ip_liberator']),
    test_suite='tests',
    tests_require=test_requirements,
    license="GNU General Public License v3",
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Topic :: Utilities",
    ],
    url='https://github.com/wagnerluis1982/ip-liberator',
    keywords='ip-liberator, Python, Amazon AWS, cloud computing, DevOps',
)
