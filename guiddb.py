"""Logic for working with Binarly's guiddb.json GUIDs for proprietary EFI types"""

import json
from os import path
from pathlib import Path


def parse_guiddb() -> dict:
    """Open Binarly's guiddb.json and return a dictionary of GUIDs"""

    current_dir = Path(__file__).parent.resolve()
    guiddb_path = path.join(current_dir, "guiddb/guids.json")
    with open(guiddb_path, "r", encoding="utf-8") as f:
        guiddb = json.load(f)

    guids = {}
    for guid_name, guid in guiddb.items():
        guids[(
            guid[0].to_bytes(4, "little")
            + guid[1].to_bytes(2, "little")
            + guid[2].to_bytes(2, "little")
            + guid[3].to_bytes(1, "little")
            + guid[4].to_bytes(1, "little")
            + guid[5].to_bytes(1, "little")
            + guid[6].to_bytes(1, "little")
            + guid[7].to_bytes(1, "little")
            + guid[8].to_bytes(1, "little")
            + guid[9].to_bytes(1, "little")
            + guid[10].to_bytes(1, "little")
        )] = guid_name

    return guids
