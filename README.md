# JSON Redactor Package

This is a simple package to process JSON files/input and redact values for keys that are deemed "sensitive"

Built as a technical assessment.

# Installation
1. Clone the repo from github:

- ssh:
`git clone git@github.com:KaitCrawford/JSON-Redactor.git`

- https:
`git clone https://github.com/KaitCrawford/JSON-Redactor.git`

3. Navigate into the repo directory:
`cd JSON-Redactor`

4. Create a virtual environment (using your prefered version of python >= 3.9):
`python3.10 -m venv ve`

5. Activate the virtual environment:
`source ve/bin/activate`

6. Install the package:
`pip install .`

# Usage
To mask values for email and msisdn keys in a json file:
```
json_redactor --keys email,msisdn path/to/input/file.json
```

To provide input via stdin:
```
cat path/to/file.json | json_redactor --keys email,msisdn
```

To provide keys from a file (the keys must be on the first line in a comma separated list)
```
json_redactor --key-file path/to/keys.txt path/to/input/file.json
```

To hash values using with a deterministic SHA-256 hash:
```
json_redactor --keys email,msisdn --hash path/to/input/file.json
```
