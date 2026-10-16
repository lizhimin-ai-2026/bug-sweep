from . import config
from . import svc_b

SETTINGS_SOURCE = "settings.json"


def load_config(path):
    try:
        return config.read_json(path)
    except Exception:
        pass


def load_and_record(path, event_name):
    result = load_config(path)
    svc_b.record_event(event_name, result)
    return result
