![Banner](banner.png)

# misconfig-SensitiveDataInConfigScanner
Scans configuration files (e.g., YAML, JSON, .env) for accidentally exposed sensitive data like API keys, passwords, and secrets using regex patterns and entropy analysis. Can integrate with pre-commit hooks to prevent sensitive data from being committed to repositories. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-sensitivedatainconfigscanner`

The tool uses only the Python standard library, so there is nothing else to install.

## Usage
`python3 main.py FILE [-v] [-e] [-t THRESHOLD]`

Findings are reported by file, line, and pattern name only. A found value is never printed, in the plain output or in the entropy branch.

Matching reports every match of every pattern on a line, not only the first. The private key pattern covers the RSA, EC, DSA, OpenSSH, and generic `PRIVATE KEY` headers.

With `-e`, entropy analysis runs as its own detection method: candidate tokens on every line are entropy tested whether or not a keyword pattern matched them, and tokens above the threshold are reported under the pattern name `high_entropy`. The entropy figure printed for a keyword finding is additional detail for that finding.

## Exit codes

- `0`: the file was scanned and no sensitive data was found.
- `1`: sensitive data was found, or the scan could not be performed. A missing file, a directory target, and a file that cannot be decoded as text all exit 1 with a scan error, and an empty file exits 1 with a "Nothing was scanned" line. None of those cases is reported as a clean scan, so the documented pre-commit use blocks a commit when sensitive data is found or when the scan failed.

## Parameters
- `-h`: Show help message and exit
- `filepath`: The path to the configuration file (positional, required).
- `-v`: Enable verbose logging.
- `-e`: Enable entropy checks: entropy figures for regex findings, plus the general entropy scan described above.
- `-t`: Set the entropy threshold (default: 4.0).

## License
Copyright (c) ShadowStrikeHQ
