from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("lunalib/requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="lunalib",
    version="1.0.0",
    author="Ling Lin",
    author_email="taellinglin@gmail.com",
    description="A Complete Cryptocurrency Wallet and Mining System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/taellinglin/LunaLib",
    project_urls={
        "Bug Tracker": "https://github.com/taellinglin/LunaLib/issues",
        "Documentation": "https://linglin.art/docs/luna-lib",
        "Source Code": "https://github.com/taellinglin/LunaLib",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "luna-wallet=luna_lib.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "lunalib": ["py.typed"],
    },
    # Add this for universal wheels (pure Python)
    options={
        'bdist_wheel': {
            'universal': True
        }
    }
)