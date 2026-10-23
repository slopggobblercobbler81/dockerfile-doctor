from setuptools import setup, find_packages

setup(
    name="dockerfile-doctor",
    version="1.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "dockerfile-doctor=dockerfile_doctor.cli:main",
        ],
    },
)
