import codecs
from setuptools import setup

with open('requirements.txt') as requirements_file:
    requirements = requirements_file.read().splitlines()

with codecs.open("README.md", 'r', encoding='utf-8') as readme_file:
    long_description = readme_file.read()

setup(
    name="ip-liberator",
    version="0.1.1",
    author="Wagner Macedo",
    author_email="wagnerluis1982@gmail.com",
    description="Command line script to update AWS Security Groups rules",
    long_description=long_description,
    py_modules = ['ip_liberator'],
    entry_points={
        'console_scripts': [
            'ip-liberator = ip_liberator:main'
        ],
    },
    install_requires=requirements,
    classifiers=(
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Topic :: Utilities",
    ),
)
