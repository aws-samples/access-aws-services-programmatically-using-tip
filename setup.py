from setuptools import find_packages, setup

from src.config import COMMAND_NAME

setup(
    name="tip-cli",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    description="CLI to access AWS services using trusted identity propagation",
    author="Roberto Migli, Bruno Corijn, Alessandro Fior",
    author_email="rmigli@amazon.com, bcorijn@amazon.com, alefior@amazon.com",
    entry_points={
        "console_scripts": [
            f"{COMMAND_NAME}=src.main:cli",
        ],
    },
    install_requires=[
        "boto3>=1.34.91, <2.0.0",
        "botocore>=1.34.91, <2.0.0",
        "click~=8.1.7",
        "PyJWT>=2.8.0, <3.0.0",
        "requests>=2.31.0, <3.0.0",
        "setuptools>=49.2.1",
        "chardet>=5.2.0, <6.0.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
