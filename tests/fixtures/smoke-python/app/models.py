from dataclasses import dataclass


@dataclass
class Note:
    region: str = ""
    remark: str = ""
    source: str = ""
    weight: int = 0
    slug: str = ""
    weight_kg: float = 0.0
    priority: int = 2
    label: str = ""
    tag: str = ""
    fingerprint: str = ""
    length: int = 0


REGION_NAMES = [
    "norway",
    "chile",
    "iceland",
    "菲律宾波利略岛（Polillo）",
]
