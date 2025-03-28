import argparse
import logging
import os
import re
import json
import yaml
import base64
import hashlib
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
    "ssh_private_key": r"-----BEGIN RSA PRIVATE KEY-----",
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
        entropy -= probability * (probability).log2()

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
        match = re.search(pattern, line)
        if match:
            matches.append((name, match.group(2) if len(match.groups()) >= 2 else match.group(0)))  # Extract actual value
    return matches


def scan_file(filepath: str, patterns: dict) -> List[Tuple[str, int, str, str]]:
    """
    Scans a file for sensitive data.

    Args:
        filepath (str): The path to the file to scan.
        patterns (dict): A dictionary of regex patterns to use.

    Returns:
        List[Tuple[str, int, str, str]]: A list of tuples, where each tuple contains the filename, line number,
                                      pattern name, and the matched value.
    """
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                matches = scan_line(line, patterns)
                for name, value in matches:
                    findings.append((filepath, i + 1, name, value))
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
    return findings


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
        findings = scan_file(args.filepath, PATTERNS)

        if findings:
            print("Sensitive data found:")
            for filepath, line_number, pattern_name, value in findings:
                print(f"  File: {filepath}")
                print(f"  Line: {line_number}")
                print(f"  Pattern: {pattern_name}")
                print(f"  Value: {value}")

                if args.entropy:
                    entropy = calculate_entropy(value)
                    print(f"  Entropy: {entropy:.2f}")
                    if entropy > args.threshold:
                        print("  [WARNING] High entropy detected!")
                print("-" * 20)

        else:
            print("No sensitive data found.")

    except ValueError as e:
        logging.error(f"Input error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()


# Usage Examples:

# 1. Basic usage:
#    python misconfig-SensitiveDataInConfigScanner.py config.yaml

# 2. Verbose mode:
#    python misconfig-SensitiveDataInConfigScanner.py config.yaml -v

# 3. With entropy check:
#    python misconfig-SensitiveDataInConfigScanner.py config.yaml -e

# 4. With custom entropy threshold:
#    python misconfig-SensitiveDataInConfigScanner.py config.yaml -e -t 4.5

# To integrate with pre-commit hooks:

# 1.  Install pre-commit: pip install pre-commit
# 2.  Create a .pre-commit-config.yaml file in your repository:

# ```yaml
# repos:
#   - repo: local
#     hooks:
#       - id: sensitive-data-scan
#         name: Scan for sensitive data
#         entry: python misconfig-SensitiveDataInConfigScanner.py
#         language: system
#         files: \.(yaml|json|env)$  # Apply to YAML, JSON, and .env files
#         pass_filenames: true
#         stages: [commit]
# ```

# 3.  Run pre-commit install
# Now, every time you commit, the script will run and prevent commits if sensitive data is found.