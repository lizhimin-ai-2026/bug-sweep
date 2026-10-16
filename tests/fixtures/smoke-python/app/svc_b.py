from . import svc_a


def record_event(event_name, payload):
    return {
        "event": event_name,
        "payload": payload,
        "source": svc_a.SETTINGS_SOURCE,
    }
