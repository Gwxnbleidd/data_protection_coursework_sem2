import pathlib
import tkinter as tk
from tkinter import filedialog, messagebox

from core.electronic_signature import ElectronicSignature
from gui.choice_key_window import ChoiseKeyWindow


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Электронная подпись")
        self.geometry("400x400")

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x_val, y_val = 250, 150

        # Вычисляем координаты для центрирования окна
        x = (screen_width // 2) - (x_val // 2)
        y = (screen_height // 2) - (y_val // 2)

        # Устанавливаем геометрию окна
        self.geometry(f'{x_val}x{y_val}+{x}+{y}')

        self.checkSignatureButton = tk.Button(self, text="Проверить документ", command=self._signalCheckSignatureDocument)
        self.signSignatureButton = tk.Button(self, text="Подписать документ", command=self._signalSignDocument)
        self.fio_label = tk.Label(self, text="А-13-21 Гайчуков Дмитрий")

        self.checkSignatureButton.pack(pady=10)
        self.signSignatureButton.pack(pady=10)
        self.fio_label.pack(pady=10)

    def _signalSignDocument(self):
        self.choiseKeyWindow = ChoiseKeyWindow()
        self.choiseKeyWindow.show()

    def _signalCheckSignatureDocument(self):
        fileName = filedialog.askopenfilename(title="Выберите файл")
        signatureFileName = filedialog.askopenfilename(title="Укажите путь к файлу с подписью")
        keysFolderName = filedialog.askdirectory(title="Выберите папку, хранящую публичный ключ")

        electronic_signature = ElectronicSignature()

        verifyStatus = electronic_signature.verify(pathlib.Path(fileName), pathlib.Path(signatureFileName),
                                                   pathlib.Path(keysFolderName + '/public_key'))

        message = (
            f"Файл {fileName.title()}, был подписан пользователем {verifyStatus.user_name}"
            if verifyStatus.status
            else f"Файл {fileName.title()}, был кем-то изменен, после подписания пользователем {verifyStatus.user_name}")

        messagebox.showinfo("Информация", message)
