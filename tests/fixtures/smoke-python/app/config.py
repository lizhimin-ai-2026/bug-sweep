import json


def read_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
