from setuptools import setup, find_packages

setup(
    name="luna_lib",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "cryptography>=3.4.0",
        "Pillow>=8.0.0",  # For QR codes
    ],
    author="Luna Crypto",
    author_email="taellinglin@gmail.com",
    description="Complete cryptocurrency wallet and mining system",
    keywords="cryptocurrency wallet mining blockchain",
    python_requires=">=3.7",
)