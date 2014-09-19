from setuptools import setup


setup(
    name="tlsenum",
    version="0.1-dev",
    py_modules=["tlsenum"],
    install_requires=[
        "Click",
    ],
    entry_points="""
        [console_scripts]
        tlsenum=tlsenum:cli
    """,
)
