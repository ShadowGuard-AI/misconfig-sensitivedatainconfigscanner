# misconfig-SensitiveDataInConfigScanner
Scans configuration files (e.g., YAML, JSON, .env) for accidentally exposed sensitive data like API keys, passwords, and secrets using regex patterns and entropy analysis. Can integrate with pre-commit hooks to prevent sensitive data from being committed to repositories. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-sensitivedatainconfigscanner`

## Usage
`./misconfig-sensitivedatainconfigscanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose logging.
- `-e`: Enable entropy checks on found strings
- `-t`: No description provided

## License
Copyright (c) ShadowStrikeHQ
