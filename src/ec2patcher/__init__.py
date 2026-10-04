"""EC2Patcher - local GUI for CVE analysis and patching of EC2 servers over SSH."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ec2patcher")  # the version lives only in pyproject.toml
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0+unknown"
