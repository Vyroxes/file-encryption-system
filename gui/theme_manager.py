import os


class ThemeManager:
    BUILTIN_THEMES = {
        "light",
        "dark",
    }

    def __init__(self, target, theme_dir="theme"):
        self.target = target
        self.theme_dir = theme_dir

    def available_themes(self) -> list[str]:
        if not os.path.isdir(self.theme_dir):
            return []

        themes = [
            os.path.splitext(filename)[0]
            for filename in os.listdir(self.theme_dir)
            if filename.lower().endswith(".qss")
        ]

        return sorted(
            themes,
            key=str.casefold,
        )

    def custom_themes(self) -> list[str]:
        return [
            theme
            for theme in self.available_themes()
            if theme.casefold()
            not in self.BUILTIN_THEMES
        ]

    def load_theme(self, theme: str) -> bool:
        if theme not in self.available_themes():
            return False

        path = os.path.join(
            self.theme_dir,
            f"{theme}.qss",
        )

        try:
            with open(
                path,
                "r",
                encoding="utf-8",
            ) as file:
                stylesheet = file.read()
        except OSError:
            return False

        self.target.setStyleSheet(
            stylesheet
        )

        return True

    @staticmethod
    def display_name(theme: str) -> str:
        return (
            theme
            .replace("_", " ")
            .replace("-", " ")
            .title()
        )