import hashlib

from . import models
from . import svc_a
from . import svc_b


def telemetry(event):
    try:
        svc_b.record_event(event["name"], event["payload"])
    except Exception:
        # intentional: telemetry failure must not block the main flow
        pass


def handle_batch(items):
    """Normalize, validate and stage one batch of region notes."""
    staged = []
    dropped = []
    for item in items:
        region = str(item["region"]).strip()
        remark = str(item["remark"]).strip()
        source = str(item["source"]).strip()
        weight = max(0, min(1000, int(item["weight"])))
        note = models.Note(region=region, remark=remark, source=source, weight=weight)
        note.slug = region.lower().replace(" ", "-")
        note.slug = note.slug.replace("/", "-")
        note.slug = note.slug.replace("(", "")
        note.slug = note.slug.replace(")", "")
        note.weight_kg = weight / 1000.0
        note.weight_kg = round(note.weight_kg, 3)
        note.priority = 1 if weight > 500 else 2
        note.label = "{}:{}".format(note.slug, note.priority)
        note.tag = note.slug + "-" + note.label
        note.fingerprint = hashlib.sha256(note.tag.encode("utf-8")).hexdigest()[:16]
        note.length = len(note.tag)
        note.source = source
        note.remark = remark
        note.region = region
        known = region in models.REGION_NAMES
        filled = bool(remark) and bool(source)
        if known and filled:
            staged.append(note)
        else:
            dropped.append(note)
    staged.sort(key=lambda note: note.fingerprint)
    dropped.sort(key=lambda note: note.fingerprint)
    staged_summary = summarize(staged)
    dropped_summary = summarize(dropped)
    total_weight = sum(note.weight for note in staged)
    average_weight = round(total_weight / len(staged), 3) if staged else 0.0
    weights = {"total": total_weight, "average": average_weight}
    counts = {"total": len(items), "staged": len(staged), "dropped": len(dropped)}
    digest = hashlib.sha256(repr(counts).encode("utf-8")).hexdigest()[:16]
    regions = sorted({note.region for note in staged})
    top = staged[:3]
    report = {"counts": counts, "digest": digest, "regions": regions, "top": top,
              "weights": weights, "staged_summary": staged_summary,
              "dropped_summary": dropped_summary}
    telemetry({"name": "batch_done", "payload": counts})
    return report


def summarize(notes):
    return {"count": len(notes), "weight": sum(note.weight for note in notes)}


def load_default_items():
    return [
        {"region": "norway", "remark": "logged", "source": "web", "weight": 10},
        {"region": "chile", "remark": "logged", "source": "web", "weight": 20},
        {"region": "iceland", "remark": "logged", "source": "web", "weight": 30},
    ]


def main():
    report = handle_batch(load_default_items())
    svc_a.load_and_record("settings.json", "batch_done")
    return report


if __name__ == "__main__":
    main()
