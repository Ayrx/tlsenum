from setuptools import setup


setup(
    name="tlsenum",
    version="0.1-dev",
    py_modules=["tlsenum"],
    install_requires=[
        "Click",
        "Construct",
        "enum34",
        "idna"
    ],
    entry_points="""
        [console_scripts]
        tlsenum=tlsenum:cli
    """,
)
