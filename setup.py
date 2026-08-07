from setuptools import setup, find_packages

setup(
    name="goods-dragon",
    version="2.0.0",
    packages=find_packages(),
    py_modules=["main"],
    install_requires=[
        "requests",
        "dnspython",
        "flask",
        "beautifulsoup4",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "dragon=main:main",
        ],
    },
)
