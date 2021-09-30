"""
This is a script for updating the formal schema file - schema.json
"""
import json
import pathlib

import mwcp


def main():
    schema_json = pathlib.Path(mwcp.__file__).parent / "config" / "schema.json"

    with schema_json.open("w") as fo:
        json.dump(mwcp.schema(), fo, indent=4)


if __name__ == "__main__":
    main()
