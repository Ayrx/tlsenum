from __future__ import absolute_import, division, print_function

from setuptools import setup, find_packages

setup(
    name="tlsenum",
    description="A TLS ciphersuite enumeration tool.",
    version="0.2",
    install_requires=[
        "Click",
        "Construct",
        "enum34",
        "idna",
        "six"
    ],
    entry_points="""
        [console_scripts]
        tlsenum=tlsenum:cli
    """,
    packages=find_packages(exclude=["tests*"]),
    license="MIT",
    url="https://github.com/Ayrx/tlsenum",
    author="Terry Chia",
    author_email="terrycwk1994@gmail.com",
    classifiers=[
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Security",
        "Topic :: Security :: Cryptography"
    ],
)
