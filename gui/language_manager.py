import json
import os

from PySide6.QtCore import QSettings


class LanguageManager:
    def __init__(self, settings: QSettings, lang_dir="lang"):
        self.settings = settings
        self.lang_dir = lang_dir
        self.translations = {}
        self.current_lang = self.settings.value("language", "en")

        self.load_language(self.current_lang)

    def load_language(self, lang: str):
        path = os.path.join(self.lang_dir, f"{lang}.json")
        if not os.path.exists(path):
            return

        with open(path, "r", encoding="utf-8") as f:
            self.translations = json.load(f)

        self.current_lang = lang
        self.settings.setValue("language", lang)

    def t(self, key: str) -> str:
        return self.translations.get(key, key)