import os

from PySide6.QtCore import QSettings


class HistoryManager:
    SETTINGS_KEY = "recent_items"

    def __init__(self, settings: QSettings):
        self.settings = settings

    def get_limit(self) -> int:
        return self.settings.value("history_limit", 10, type=int)

    def set_limit(self, limit: int):
        self.settings.setValue("history_limit", max(1, limit))
        self._trim()

    def load(self) -> list[dict]:
        return self.settings.value(self.SETTINGS_KEY, [], type=list)

    def save(self, items: list[dict]):
        self.settings.setValue(self.SETTINGS_KEY, items)

    def add(self, path: str, item_type: str):
        if not path or not os.path.exists(path):
            return

        items = self.load()

        items = [
            item for item in items
            if not (item["path"] == path and item.get("type") == item_type)
        ]

        items.append({
            "path": path,
            "name": os.path.basename(path),
            "size": os.path.getsize(path),
            "type": item_type
        })

        type_items = [item for item in items if item.get("type") == item_type]
        other_items = [item for item in items if item.get("type") != item_type]

        type_items = type_items[-self.get_limit():]

        self.save(other_items + type_items)

    def remove(self, path: str, item_type: str):
        items = [
            item for item in self.load()
            if not (item["path"] == path and item.get("type") == item_type)
        ]
        self.save(items)

    def clear(self, item_type: str):
        items = [item for item in self.load() if item.get("type") != item_type]
        self.save(items)

    def _trim(self):
        limit = self.get_limit()
        items = self.load()
        counts = {}
        trimmed = []

        for item in reversed(items):
            item_type = item.get("type")
            count = counts.get(item_type, 0)

            if count < limit:
                trimmed.append(item)
                counts[item_type] = count + 1

        self.save(list(reversed(trimmed)))