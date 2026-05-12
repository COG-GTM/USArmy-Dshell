from setuptools import find_packages, setup

setup(
    name="Dshell",
    version="3.2.3",
    author="USArmyResearchLab",
    description="An extensible network forensic analysis framework",
    url="https://github.com/USArmyResearchLab/Dshell",
    python_requires='>=3.9',
    packages=find_packages(),
    package_data={
        "dshell": ["data/dshellrc", "data/GeoIP/readme.txt"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Topic :: Security",
    ],
    install_requires=[
        # Minimum-version floors close out known-fixed CVEs in the dependency
        # tree (STIG V-220631 / NIST SI-2, RA-5, SA-22).
        "geoip2>=4.7.0",
        "pcapy-ng>=1.0.9",
        "pypacker>=5.2",
        "pyopenssl>=24.0.0",
        "elasticsearch>=7.17.0,<9.0",
        "tabulate>=0.9.0",
    ],
    entry_points={
        "console_scripts": [
            "dshell-decode = dshell.decode:main_command_line",
        ],
        "dshell_plugins": [],
    },
    scripts=[
        "scripts/dshell",
    ],
)
