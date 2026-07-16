from pathlib import Path

from setuptools import find_packages, setup


REQUIREMENTS_PATH = Path(__file__).with_name("requirements.txt")

# requirements.txt 是运行时依赖的唯一来源，避免 pip 安装与包元数据发生版本漂移。
INSTALL_REQUIRES = [
    line
    for raw_line in REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines()
    if (line := raw_line.strip()) and not line.startswith("#")
]

setup(
    name="saga",
    version="1.0.1",
    author="Georgios Syros, Anshuman Suri",
    author_email="syros.g@northeastern",
    description="A project for secure and governable autonomous agent communication.",
    packages=find_packages(),
    install_requires=INSTALL_REQUIRES,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
)
