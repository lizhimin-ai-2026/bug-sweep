from app.handler import handle_batch
from app.models import Note


def test_handle_batch_stages_known_regions():
    items = [
        {"region": "norway", "remark": "logged", "source": "web", "weight": 10},
    ]
    report = handle_batch(items)
    assert report["counts"]["staged"] == 1


def test_note_defaults():
    note = Note(region="norway", remark="logged")
    assert note.priority == 2
