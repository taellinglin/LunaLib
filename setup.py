from setuptools import setup, find_packages

setup(
    name="lunalib",
    version="1.9.1",
    author="Ling Lin",
    author_email="",
    description="Cryptocurrency Ecosystem library (LunaLib)",
    long_description="A modular cryptocurrency ecosystem library including blockchain, wallet, mining, storage, and transaction management.",
    long_description_content_type="text/markdown",
    url="",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests",
        "numpy",
        "pytest",
        "pandas",
        "tqdm",
        "base58",
        "colorama",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)