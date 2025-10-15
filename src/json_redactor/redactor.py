import json
import sys
from hashlib import sha256
from typing import Dict, List

import ijson
import typer
from typing_extensions import Annotated


def redact(
    input_file: Annotated[
        str, typer.Argument(help="The path to the input file (defaults to stdin)")
    ] = "",
    keys: Annotated[
        str, typer.Option(help="The sensitive keys that should be redacted")
    ] = "",
    key_file: Annotated[
        str,
        typer.Option(
            help="File containing a comma separated list of sensative keys to redact"
        ),
    ] = "",
    mask: Annotated[
        bool,
        typer.Option(
            "--mask", help='(Default) Replace sensitive values with "***Redacted***"'
        ),
    ] = None,
    hash: Annotated[
        bool,
        typer.Option(
            "--hash", help="Replace sensitive values with a deterministic sha256 hash"
        ),
    ] = None,
):

    if not keys and not key_file:
        print(
            "One of '--keys' or '--key_file' options must be provided.", file=sys.stderr
        )
        sys.exit(1)
    elif keys and key_file:
        print(
            "Only one of '--keys' or '--key_file' options must be provided.",
            file=sys.stderr,
        )
        sys.exit(1)
    elif key_file:
        # Read keys from provided file
        try:
            with open(key_file, "r") as kf:
                keys = kf.readline()
        except FileNotFoundError:
            print(f"Key file {key_file} not found.", file=sys.stderr)
            sys.exit(2)

    # Split comma separated keys into a list for key comparison
    key_list = [k.casefold() for k in keys.split(",")]

    if hash and mask:
        print(
            "Only one of '--mask' or '--hash' options must be provided.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not input_file:
        input_file = "/dev/stdin"
    try:
        with open(input_file, "rb") as f:
            print("[")
            previous_object = None
            counter = 0
            try:
                for obj in ijson.items(f, "item"):
                    if hash:
                        redacted_object = hash_sensitive_values(obj, key_list)
                    else:
                        redacted_object = mask_sensitive_values(obj, key_list)

                    # We only output an object once the next one has been processed
                    # This is necessary to ensure we stream the output in correctly formatted JSON
                    if previous_object:
                        print(f"{json.dumps(previous_object)},")
                    previous_object = redacted_object
                    counter += 1
            except ijson.IncompleteJSONError as e:
                print(
                    f"The JSON provided is invalid. Invalid object index: {counter}",
                    file=sys.stderr,
                )
                print(e, file=sys.stderr)
                sys.exit(3)
            except AttributeError as e:
                print(
                    f"The JSON provided may be invalid. Invalid object index: {counter}",
                    file=sys.stderr,
                )
                print(e, file=sys.stderr)
                sys.exit(3)
            if previous_object:
                print(json.dumps(previous_object))
            print("]")
    except FileNotFoundError:
        print(f"Input file {input_file} not found.", file=sys.stderr)
        sys.exit(2)

    sys.exit()


def mask_sensitive_values(object: Dict, sensitive_keys: List) -> Dict:
    """Recursively compares keys in dict to a list of keys that contain sensitive data. Returns dict with sensitive values masked."""
    for k, v in object.items():
        if isinstance(v, dict):
            object[k] = mask_sensitive_values(v, sensitive_keys)
        elif k.casefold() in sensitive_keys:
            object[k] = "***REDACTED***"
    return object


def hash_sensitive_values(object: Dict, sensitive_keys: List) -> Dict:
    """Recursively compares keys in dict to a list of keys that contain sensitive data. Returns dict with sensitive values hashed."""
    for k, v in object.items():
        if isinstance(v, dict):
            object[k] = hash_sensitive_values(v, sensitive_keys)
        elif k.casefold() in sensitive_keys:
            object[k] = sha256(object[k].encode("utf-8")).hexdigest()
    return object


# Assumptions:
# - The top level JSON object is always a list
# - In arbitrarily nested input, the key for a nested object will never be a sensitive key

# Concessions:
# - The output will be incomplete and malformed if some data in the input stream isn't valid
# - Printing out the errors encountered while processing the json may expose sensitive fields
