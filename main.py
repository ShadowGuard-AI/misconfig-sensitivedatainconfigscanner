import argparse
import logging
import os
import re
import sys
import math
from typing import List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common sensitive data patterns
PATTERNS = {
    "api_key": r"(?i)(api[-_]?key|key[-_]?api)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]+)['\"]?",
    "password": r"(?i)(password|pwd)\s*[:=]\s*['\"]?([a-zA-Z0-9!@#$%^&*()_-]+)['\"]?",
    "secret": r"(?i)(secret|secret[-_]?key|key[-_]?secret)\s*[:=]\s*['\"]?([a-zA-Z0-9!@#$%^&*()_-]+)['\"]?",
    "aws_access_key_id": r"(?i)aws_access_key_id\s*[:=]\s*['\"]?([A-Z0-9]+)['\"]?",
    "aws_secret_access_key": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]+)['\"]?",
    "ssh_private_key": r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----",
    "jwt": r"ey[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
}


def calculate_entropy(data: str) -> float:
    """
    Calculates the entropy of a string.
    """
    if not data:
        return 0.0

    entropy = 0.0
    data_length = len(data)
    frequency = {}

    for char in data:
        if char in frequency:
            frequency[char] += 1
        else:
            frequency[char] = 1

    for char in frequency:
        probability = frequency[char] / data_length
        entropy -= probability * math.log2(probability)

    return entropy


def scan_line(line: str, patterns: dict) -> List[Tuple[str, str]]:
    """
    Scans a single line for sensitive data using regex patterns.

    Args:
        line (str): The line to scan.
        patterns (dict): A dictionary of regex patterns to use.

    Returns:
        List[Tuple[str, str]]: A list of tuples, where each tuple contains the pattern name and the matched value.
    """
    matches = []
    for name, pattern in patterns.items():
        for match in re.finditer(pattern, line):
            groups = match.groups()
            # The value I keep is the last capture group, which for the
            # keyword patterns is the value and for the private key
            # pattern, which has no value group, is the header text
            # itself. The entropy printed in main for a key finding is
            # therefore sometimes the entropy of a header line.
            value = groups[-1] if groups and groups[-1] is not None else match.group(0)
            matches.append((name, value))
    return matches


# Candidate tokens for the general entropy scan: long runs of the
# characters secrets are usually built from. Every such token on a
# line is entropy tested on its own when entropy checking is enabled,
# whether or not any keyword pattern matched it.
ENTROPY_TOKEN_PATTERN = r"[A-Za-z0-9_+/=\-]{12,}"


def entropy_matches(line: str, threshold: float, already_matched) -> List[Tuple[str, str]]:
    """
    Entropy tests the candidate tokens on a line and returns the ones
    above the threshold that no keyword pattern already reported.
    """
    results = []
    seen = set(already_matched)
    for match in re.finditer(ENTROPY_TOKEN_PATTERN, line):
        token = match.group(0)
        # Deduplication compares whole tokens against the values the
        # keyword patterns already returned, but a keyword value is
        # often a piece of a longer token, quotes trimmed, characters
        # outside its set cut away. The full token then fails this
        # test and can be reported a second time as high entropy on
        # the same line.
        if token in seen:
            continue
        seen.add(token)
        if calculate_entropy(token) > threshold:
            results.append(("high_entropy", token))
    return results


def scan_file(filepath: str, patterns: dict, entropy_enabled: bool = False, threshold: float = 4.0):
    """
    Scans a file for sensitive data.

    Args:
        filepath (str): The path to the file to scan.
        patterns (dict): A dictionary of regex patterns to use.
        entropy_enabled (bool): Also entropy test candidate tokens on
            every line and report those above the threshold.
        threshold (float): The entropy threshold for that scan.

    Returns:
        A pair (findings, lines_scanned). Each finding is a tuple of
        filename, line number, pattern name, and the matched value.
        The value is used internally, for example for its entropy
        figure, and is never printed.

    Raises:
        OSError, UnicodeDecodeError: If the file cannot be read as
            text. Callers must treat that as a failed scan, not a
            clean one.
    """
    findings = []
    lines_scanned = 0
    with open(filepath, 'r', encoding='utf-8') as f:
        # Everything I do is per line. A key on one line and its value
        # on the next, a common YAML shape, never meets any pattern,
        # because each pattern needs the name, the separator, and the
        # value on the same line. Multi line values are invisible to
        # me in the other direction too.
        for i, line in enumerate(f):
            lines_scanned += 1
            # The password and secret patterns stop their value at the
            # first character outside their set, so a value containing a
            # dot or a comma is captured only up to that point. What I
            # report finding, and what main measures the entropy of, can
            # be a fragment of the value actually in the file.
            matches = scan_line(line, patterns)
            if entropy_enabled:
                matches = matches + entropy_matches(
                    line, threshold, [value for _, value in matches]
                )
            for name, value in matches:
                findings.append((filepath, i + 1, name, value))
    return findings, lines_scanned


def validate_input(filepath: str) -> None:
    """
    Validates the input filepath.

    Args:
        filepath (str): The filepath to validate.

    Raises:
        ValueError: If the filepath is not a string or does not exist.
    """
    if not isinstance(filepath, str):
        raise ValueError("Filepath must be a string.")
    if not os.path.exists(filepath):
        raise ValueError(f"File not found: {filepath}")
    if os.path.isdir(filepath):
        raise ValueError(f"Target is a directory, not a file: {filepath}. Nothing was scanned.")


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description='Scans configuration files for sensitive data.')
    parser.add_argument('filepath', help='The path to the configuration file.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging.')
    parser.add_argument('-e', '--entropy', action='store_true', help='Enable entropy checks on found strings')
    parser.add_argument('-t', '--threshold', type=float, default=4.0, help='Set the entropy threshold (default: 4.0)')

    return parser


def main() -> None:
    """
    Main function to execute the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        validate_input(args.filepath)
    except ValueError as e:
        logging.error(f"Input error: {e}")
        sys.exit(1)

    try:
        findings, lines_scanned = scan_file(
            args.filepath, PATTERNS,
            entropy_enabled=args.entropy, threshold=args.threshold,
        )
    except (OSError, UnicodeDecodeError) as e:
        logging.error(f"Could not scan '{args.filepath}': {e}. Nothing was scanned.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

    if lines_scanned == 0:
        print("Nothing was scanned: the file contains no lines.")
        sys.exit(1)

    if findings:
        # Found values are never printed, in any branch. Findings are
        # reported by file, line, and pattern name only.
        print("Sensitive data found:")
        for filepath, line_number, pattern_name, value in findings:
            print(f"  File: {filepath}")
            print(f"  Line: {line_number}")
            print(f"  Pattern: {pattern_name}")

            if args.entropy:
                # This runs for every finding whenever the entropy flag is
                # set, including plain keyword findings, and the warning
                # below compares them against a threshold meant for the
                # token scan. Without the flag the same threshold argument
                # still exists but changes nothing at all, because the token
                # scan is the only other place it is read.
                entropy = calculate_entropy(value)
                print(f"  Entropy: {entropy:.2f}")
                if entropy > args.threshold:
                    print("  [WARNING] High entropy detected!")
            print("-" * 20)
        sys.exit(1)

    print("No sensitive data found.")
    sys.exit(0)


if __name__ == "__main__":
    main()


# Usage Examples:

# 1. Basic usage:
#    python3 main.py config.yaml

# 2. Verbose mode:
#    python3 main.py config.yaml -v

# 3. With entropy check:
#    python3 main.py config.yaml -e

# 4. With custom entropy threshold:
#    python3 main.py config.yaml -e -t 4.5

# To integrate with pre-commit hooks:

# 1.  Install pre-commit: pip install pre-commit
# 2.  Create a .pre-commit-config.yaml file in your repository:

# ```yaml
# repos:
#   - repo: local
#     hooks:
#       - id: sensitive-data-scan
#         name: Scan for sensitive data
#         entry: python3 main.py
#         language: system
#         files: \.(yaml|json|env)$  # Apply to YAML, JSON, and .env files
#         pass_filenames: true
#         stages: [commit]
# ```

# 3.  Run pre-commit install
# Now, every time you commit, the script will run and prevent commits if sensitive data is found.