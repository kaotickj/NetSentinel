# setup.py

from setuptools import setup, find_packages

setup(
    name="netsentinel",
    version="1.0.0",
    description="Covert Internal Reconnaissance Framework for Red Teams",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Kaotick Jay",
    author_email="kaotickj@protonmail.com",
    url="https://github.com/kaotickj/netsentinel",
    packages=find_packages(exclude=["tests*", "examples*", "docs*"]),
    include_package_data=True,
    install_requires=[
        "scapy>=2.4.5",
        "colorama>=0.4.6",
        "impacket>=0.11.0",
        "ldap3>=2.9.1",
        "smbprotocol>=1.15.0"
    ],
    python_requires='>=3.7',
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring"
    ],
    entry_points={
        "console_scripts": [
            "netsentinel=main:main"
        ]
    },
    license="GPLv3"
)

