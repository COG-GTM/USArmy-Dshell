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
        "geoip2",
        "pcapy-ng",
        "pypacker",
        "pyopenssl",
        "elasticsearch",
        "tabulate",
        # Segment extractor/pusher tooling
        "cryptography",  # AES-256-GCM encryption at rest (STIG V-222659)
        "redis",         # RedisPusher
        "requests",      # RESTAPIPusher
        "pyyaml",        # config file parsing
    ],
    extras_require={
        # Optional message-bus transports for the segment pusher.
        "kafka": ["kafka-python"],
        "confluent": ["confluent-kafka"],
    },
    entry_points={
        "console_scripts": [
            "dshell-decode = dshell.decode:main_command_line",
            "dshell-segment = dshell.segment_cli:main",
        ],
        "dshell_plugins": [],
    },
    scripts=[
        "scripts/dshell",
    ],
)
