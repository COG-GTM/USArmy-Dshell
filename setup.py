from setuptools import find_packages, setup

setup(
    name="Dshell",
    version="3.2.3",
    author="USArmyResearchLab",
    description="An extensible network forensic analysis framework",
    url="https://github.com/USArmyResearchLab/Dshell",
    python_requires='>=3.8',
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
        "geoip2>=4.0.0",
        "pcapy-ng>=1.0.0",
        "pypacker>=5.0",
        "pyopenssl>=21.0.0",  # Minimum version to ensure modern OpenSSL (CVE-2014-0160 mitigation)
        "elasticsearch>=7.0.0",  # Modern client with security features
        "tabulate>=0.8.0",
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
