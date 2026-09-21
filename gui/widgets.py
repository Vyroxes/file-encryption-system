import os
import sys

from PySide6.QtCore import (
    QEasingCurve, QEvent, Property, Qt, QVariantAnimation, Signal,
)
from PySide6.QtGui import QColor, QFontMetrics, QTextDocument
from PySide6.QtWidgets import (
    QApplication, QComboBox, QLabel, QPushButton, QSpinBox, QStyle, QStyledItemDelegate,
)


STREAMING_ROLE = Qt.ItemDataRole.UserRole + 1
ALGORITHM_HEADER_ROLE = Qt.ItemDataRole.UserRole + 2


class DescriptionDelegate(QStyledItemDelegate):
    def sizeHint(self, option, index):
        size = super().sizeHint(option, index)

        text = index.data(Qt.ItemDataRole.DisplayRole) or ""

        if not text:
            return size

        width = option.rect.width()

        if width <= 0 and option.widget:
            width = option.widget.columnWidth(index.column())

        document = QTextDocument()
        document.setDefaultFont(option.font)
        document.setDocumentMargin(0)
        document.setPlainText(text)
        document.setTextWidth(max(1, width - 24))

        size.setHeight(
            max(
                size.height(),
                int(document.size().height()) + 12,
            )
        )

        return size

class StreamingComboDelegate(QStyledItemDelegate):
    badge_spacing = 4
    badge_font_size = 9
    badge_color = "#16a34a"

    def paint(self, painter, option, index):
        if index.data(ALGORITHM_HEADER_ROLE):
            painter.save()

            combo = self.parent()

            background_color = combo.property(
                "headerBackgroundColor"
            )
            text_color = combo.property(
                "headerTextColor"
            )
            divider_color = combo.property(
                "headerDividerColor"
            )

            painter.fillRect(
                option.rect,
                background_color,
            )

            font = option.font
            font.setBold(True)
            font.setPointSize(
                max(8, font.pointSize() - 1)
            )

            painter.setFont(font)
            painter.setPen(text_color)

            text_rect = option.rect.adjusted(
                6,
                5,
                -6,
                -5,
            )

            painter.drawText(
                text_rect,
                Qt.AlignmentFlag.AlignVCenter
                | Qt.AlignmentFlag.AlignLeft,
                index.data(
                    Qt.ItemDataRole.DisplayRole
                ),
            )

            painter.restore()
            return

        self.initStyleOption(option, index)

        text = option.text
        is_streaming = bool(index.data(STREAMING_ROLE))

        option.text = ""

        style = option.widget.style() if option.widget else QApplication.style()
        style.drawControl(
            QStyle.ControlElement.CE_ItemViewItem,
            option,
            painter,
            option.widget,
        )

        text_rect = option.rect.adjusted(6, 0, -6, 0)

        painter.save()

        painter.setPen(option.palette.text().color())
        painter.setFont(option.font)

        painter.drawText(
            text_rect,
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            text,
        )

        if is_streaming:
            text_metrics = QFontMetrics(option.font)
            text_width = text_metrics.horizontalAdvance(text)

            badge_font = option.font
            badge_font.setPointSize(self.badge_font_size)
            badge_font.setBold(True)

            painter.setFont(badge_font)
            painter.setPen(QColor(self.badge_color))

            badge_x = text_rect.left() + text_width + self.badge_spacing

            badge_rect = text_rect
            badge_rect.setLeft(badge_x)

            painter.drawText(
                badge_rect,
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                "Ⓢ",
            )

        painter.restore()

    def sizeHint(self, option, index):
        size = super().sizeHint(option, index)

        if index.data(ALGORITHM_HEADER_ROLE):
            size.setHeight(32)
        else:
            size.setHeight(30)

        return size

class AnimatedLabel(QLabel):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)

        self._normal_color = QColor("transparent")
        self._hover_color = QColor("transparent")
        self._normal_border_color = QColor("#505050")
        self._hover_border_color = QColor("#353535")

        self._current_color = QColor(self._normal_color)
        self._current_border_color = QColor(self._normal_border_color)

        self._hover_duration = 160
        self._hovered = False
        self._updating_style = False

        self._background_animation = QVariantAnimation(self)
        self._background_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self._background_animation.valueChanged.connect(self._update_background)

        self._border_animation = QVariantAnimation(self)
        self._border_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self._border_animation.valueChanged.connect(self._update_border)

    def enterEvent(self, event):
        self._hovered = True
        self._animate(
            self._hover_color,
            self._hover_border_color,
        )
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hovered = False
        self._animate(
            self._normal_color,
            self._normal_border_color,
        )
        super().leaveEvent(event)

    def _animate(self, background, border):
        self._background_animation.stop()
        self._border_animation.stop()

        self._background_animation.setDuration(self._hover_duration)
        self._background_animation.setStartValue(self._current_color)
        self._background_animation.setEndValue(background)

        self._border_animation.setDuration(self._hover_duration)
        self._border_animation.setStartValue(self._current_border_color)
        self._border_animation.setEndValue(border)

        self._background_animation.start()
        self._border_animation.start()

    def _update_background(self, color):
        self._current_color = QColor(color)
        self._apply_style()

    def _update_border(self, color):
        self._current_border_color = QColor(color)
        self._apply_style()

    def _apply_style(self):
        if self._updating_style:
            return

        self._updating_style = True

        self.setStyleSheet(
            f"""
            background-color: {self._current_color.name(QColor.NameFormat.HexArgb)};
            border: 2px dashed {self._current_border_color.name(QColor.NameFormat.HexArgb)};
            """
        )

        self._updating_style = False

    def get_normal_color(self):
        return self._normal_color

    def set_normal_color(self, color):
        self._normal_color = QColor(color)

        if not self._updating_style and not self._hovered:
            self._current_color = QColor(self._normal_color)
            self._apply_style()

    normalColor = Property(QColor, get_normal_color, set_normal_color)

    def get_hover_color(self):
        return self._hover_color

    def set_hover_color(self, color):
        self._hover_color = QColor(color)

        if not self._updating_style and self._hovered:
            self._current_color = QColor(self._hover_color)
            self._apply_style()

    hoverColor = Property(QColor, get_hover_color, set_hover_color)

    def get_normal_border_color(self):
        return self._normal_border_color

    def set_normal_border_color(self, color):
        self._normal_border_color = QColor(color)

        if not self._updating_style and not self._hovered:
            self._current_border_color = QColor(self._normal_border_color)
            self._apply_style()

    normalBorderColor = Property(
        QColor,
        get_normal_border_color,
        set_normal_border_color,
    )

    def get_hover_border_color(self):
        return self._hover_border_color

    def set_hover_border_color(self, color):
        self._hover_border_color = QColor(color)

        if not self._updating_style and self._hovered:
            self._current_border_color = QColor(self._hover_border_color)
            self._apply_style()

    hoverBorderColor = Property(
        QColor,
        get_hover_border_color,
        set_hover_border_color,
    )

    def get_hover_duration(self):
        return self._hover_duration

    def set_hover_duration(self, duration):
        self._hover_duration = duration

    hoverDuration = Property(
        int,
        get_hover_duration,
        set_hover_duration,
    )

class AnimatedComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)

        self._normal_color = QColor("#505050")
        self._hover_color = QColor("#606060")
        self._disabled_color = QColor("#bbbbbb")

        self._normal_border_color = QColor("#353535")
        self._hover_border_color = QColor("#454545")
        self._disabled_border_color = QColor("#555555")

        self._header_background_color = QColor("#252525")
        self._header_text_color = QColor("#a8a8a8")
        self._header_divider_color = QColor("#505050")

        self._current_color = QColor(self._normal_color)
        self._current_border_color = QColor(self._normal_border_color)

        self._hover_duration = 160
        self._hovered = False
        self._popup_open = False
        self._updating_style = False

        self._background_animation = QVariantAnimation(self)
        self._background_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self._background_animation.valueChanged.connect(self._update_background)

        self._border_animation = QVariantAnimation(self)
        self._border_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self._border_animation.valueChanged.connect(self._update_border)

    def enterEvent(self, event):
        self._hovered = True

        if self.isEnabled() and not self._popup_open:
            self._animate(
                self._hover_color,
                self._hover_border_color,
            )

        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hovered = False

        if self.isEnabled() and not self._popup_open:
            self._animate(
                self._normal_color,
                self._normal_border_color,
            )

        super().leaveEvent(event)

    def changeEvent(self, event):
        super().changeEvent(event)

        if event.type() == QEvent.Type.EnabledChange:
            self._background_animation.stop()
            self._border_animation.stop()

            if self.isEnabled():
                self._current_color = QColor(
                    self._hover_color if self._hovered else self._normal_color
                )
                self._current_border_color = QColor(
                    self._hover_border_color
                    if self._hovered
                    else self._normal_border_color
                )
            else:
                self._current_color = QColor(self._disabled_color)
                self._current_border_color = QColor(
                    self._disabled_border_color
                )

            self._apply_style()

    def _animate(self, background, border):
        self._background_animation.stop()
        self._border_animation.stop()

        self._background_animation.setDuration(self._hover_duration)
        self._background_animation.setStartValue(self._current_color)
        self._background_animation.setEndValue(background)

        self._border_animation.setDuration(self._hover_duration)
        self._border_animation.setStartValue(self._current_border_color)
        self._border_animation.setEndValue(border)

        self._background_animation.start()
        self._border_animation.start()

    def _update_background(self, color):
        self._current_color = QColor(color)
        self._apply_style()

    def _update_border(self, color):
        self._current_border_color = QColor(color)
        self._apply_style()

    def _apply_style(self):
        if self._updating_style:
            return

        self._updating_style = True

        self.setStyleSheet(
            f"""
            QComboBox {{
                background-color: {self._current_color.name(QColor.NameFormat.HexArgb)};
                border: 1px solid {self._current_border_color.name(QColor.NameFormat.HexArgb)};
            }}
            """
        )

        self._updating_style = False

    def get_normal_color(self):
        return self._normal_color

    def set_normal_color(self, color):
        self._normal_color = QColor(color)

        if not self._updating_style and self.isEnabled() and not self._hovered:
            self._current_color = QColor(self._normal_color)
            self._apply_style()

    normalColor = Property(QColor, get_normal_color, set_normal_color)

    def get_hover_color(self):
        return self._hover_color

    def set_hover_color(self, color):
        self._hover_color = QColor(color)

    hoverColor = Property(QColor, get_hover_color, set_hover_color)

    def get_disabled_color(self):
        return self._disabled_color

    def set_disabled_color(self, color):
        self._disabled_color = QColor(color)

        if not self._updating_style and not self.isEnabled():
            self._current_color = QColor(self._disabled_color)
            self._apply_style()

    disabledColor = Property(
        QColor,
        get_disabled_color,
        set_disabled_color,
    )

    def get_normal_border_color(self):
        return self._normal_border_color

    def set_normal_border_color(self, color):
        self._normal_border_color = QColor(color)

        if not self._updating_style and self.isEnabled() and not self._hovered:
            self._current_border_color = QColor(self._normal_border_color)
            self._apply_style()

    normalBorderColor = Property(
        QColor,
        get_normal_border_color,
        set_normal_border_color,
    )

    def get_hover_border_color(self):
        return self._hover_border_color

    def set_hover_border_color(self, color):
        self._hover_border_color = QColor(color)

    hoverBorderColor = Property(
        QColor,
        get_hover_border_color,
        set_hover_border_color,
    )

    def get_disabled_border_color(self):
        return self._disabled_border_color

    def set_disabled_border_color(self, color):
        self._disabled_border_color = QColor(color)

        if not self._updating_style and not self.isEnabled():
            self._current_border_color = QColor(
                self._disabled_border_color
            )
            self._apply_style()

    disabledBorderColor = Property(
        QColor,
        get_disabled_border_color,
        set_disabled_border_color,
    )

    def get_hover_duration(self):
        return self._hover_duration

    def set_hover_duration(self, duration):
        self._hover_duration = duration

    hoverDuration = Property(
        int,
        get_hover_duration,
        set_hover_duration,
    )

    def get_header_background_color(self):
        return self._header_background_color

    def set_header_background_color(self, color):
        self._header_background_color = QColor(color)
        self.view().viewport().update()

    headerBackgroundColor = Property(
        QColor,
        get_header_background_color,
        set_header_background_color,
    )


    def get_header_text_color(self):
        return self._header_text_color

    def set_header_text_color(self, color):
        self._header_text_color = QColor(color)
        self.view().viewport().update()

    headerTextColor = Property(
        QColor,
        get_header_text_color,
        set_header_text_color,
    )


    def get_header_divider_color(self):
        return self._header_divider_color

    def set_header_divider_color(self, color):
        self._header_divider_color = QColor(color)
        self.view().viewport().update()

    headerDividerColor = Property(
        QColor,
        get_header_divider_color,
        set_header_divider_color,
    )

    def showPopup(self):
        self._popup_open = True

        self._background_animation.stop()
        self._border_animation.stop()

        self._current_color = QColor(self._normal_color)
        self._current_border_color = QColor(self._normal_border_color)
        self._apply_style()

        super().showPopup()

    def hidePopup(self):
        super().hidePopup()

        self._popup_open = False
        self._hovered = self.underMouse()

        if self._hovered and self.isEnabled():
            self._animate(
                self._hover_color,
                self._hover_border_color,
            )

class AnimatedButton(QPushButton):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)

        self._normal_color = QColor("#555555")
        self._hover_color = QColor("#666666")
        self._disabled_color = QColor("#bbbbbb")
        self._current_color = QColor(self._normal_color)
        self._hover_duration = 160
        self._hovered = False
        self._updating_style = False

        self._animation = QVariantAnimation(self)
        self._animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self._animation.valueChanged.connect(self._update_color)

    def enterEvent(self, event):
        self._hovered = True

        if self.isEnabled():
            self._animate_to(self._hover_color)

        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hovered = False

        if self.isEnabled():
            self._animate_to(self._normal_color)

        super().leaveEvent(event)

    def changeEvent(self, event):
        super().changeEvent(event)

        if event.type() == QEvent.Type.EnabledChange:
            self._animation.stop()

            if self.isEnabled():
                color = self._hover_color if self._hovered else self._normal_color
            else:
                color = self._disabled_color

            self._update_color(color)

    def _animate_to(self, color):
        self._animation.stop()
        self._animation.setDuration(self._hover_duration)
        self._animation.setStartValue(self._current_color)
        self._animation.setEndValue(color)
        self._animation.start()

    def _update_color(self, color):
        self._current_color = QColor(color)

        if self._updating_style:
            return

        self._updating_style = True

        self.setStyleSheet(
            f"background-color: {self._current_color.name(QColor.NameFormat.HexArgb)};"
        )

        self._updating_style = False

    def get_normal_color(self):
        return self._normal_color

    def set_normal_color(self, color):
        self._normal_color = QColor(color)

        if not self._updating_style and self.isEnabled() and not self._hovered:
            self._animation.stop()
            self._update_color(self._normal_color)

    normalColor = Property(
        QColor,
        get_normal_color,
        set_normal_color,
    )

    def get_hover_color(self):
        return self._hover_color

    def set_hover_color(self, color):
        self._hover_color = QColor(color)

    hoverColor = Property(
        QColor,
        get_hover_color,
        set_hover_color,
    )

    def get_disabled_color(self):
        return self._disabled_color

    def set_disabled_color(self, color):
        self._disabled_color = QColor(color)

        if not self._updating_style and not self.isEnabled():
            self._animation.stop()
            self._update_color(self._disabled_color)

    disabledColor = Property(
        QColor,
        get_disabled_color,
        set_disabled_color,
    )

    def get_hover_duration(self):
        return self._hover_duration

    def set_hover_duration(self, duration):
        self._hover_duration = duration

    hoverDuration = Property(
        int,
        get_hover_duration,
        set_hover_duration,
    )

class ClickablePathLabel(AnimatedLabel):
    pathChanged = Signal()

    def __init__(self, label_type="file", placeholder=None, clear_button=None, parent=None):       
        self.label_type = label_type
        self.lang = parent.lang if parent and hasattr(parent, "lang") else None
        
        if placeholder is None:
            placeholder = self._default_placeholder()

        super().__init__(placeholder, parent)
        self.path = None
        self.clear_button = clear_button
        self.setObjectName("dragAndDropLabel")
        self.setAcceptDrops(True)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

    def _default_placeholder(self):
        if self.label_type == "file":
            return self.lang.t("file.none")
        if self.label_type == "key":
            return self.lang.t("key.none")
        if self.label_type == "private_key":
            return self.lang.t("key.private.none")
        if self.label_type == "public_key":
            return self.lang.t("key.public.none")
        if self.label_type == "signature":
            return self.lang.t("signature.none")

        return ""

    def setPath(self, path: str):
        if path and os.path.exists(path):
            self.path = path
            self.setText(path)
            self.setToolTip(f"{self.lang.t('path')}{path}\n{self.lang.t('size')}{self._safe_file_size_fmt(path)}\n{self.lang.t('double-click')}")
            if self.clear_button:
                self.clear_button.setEnabled(True)
            self.pathChanged.emit()
        else:
            self.clearPath()

    def clearPath(self):
        self.path = None
        self.setText(self._default_placeholder())
        self.setToolTip("")
        if self.clear_button:
            self.clear_button.setEnabled(False)
        self.pathChanged.emit()

    def mouseDoubleClickEvent(self, event):
        if self.path and os.path.exists(self.path):
            folder = os.path.dirname(self.path)
            if sys.platform == "win32":
                os.startfile(folder)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.setPath(path)
            event.acceptProposedAction()

    @staticmethod
    def _safe_file_size_fmt(path: str) -> str:
        try:
            num = os.path.getsize(path)
            for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
                if num < 1024.0:
                    return f"{num:.1f} {unit}"
                num /= 1024.0
            return f"{num:.1f} PiB"
        except OSError:
            return "—"

class ButtonOnlySpinBox(QSpinBox):
    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Tab, Qt.Key.Key_Backtab):
            super().keyPressEvent(event)
            return
        event.ignore()