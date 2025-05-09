import pathlib
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from core.electronic_signature import ElectronicSignature


class ChoiseKeyWindow(tk.Toplevel):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.title("Выбор ключей")

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x_val, y_val = 250, 100

        # Вычисляем координаты для центрирования окна
        x = (screen_width // 2) - (x_val // 2)
        y = (screen_height // 2) - (y_val // 2)

        # Устанавливаем геометрию окна
        self.geometry(f'{x_val}x{y_val}+{x}+{y}')

        self.generateNewKeyButton = tk.Button(self, text="Создать новые ключи", command=self._signalGenerateNewKey)
        self.usingExistingKeyButton = tk.Button(self, text="Использовать существующие ключи",
                                                command=self._signalUsingExistingKey)

        self.generateNewKeyButton.pack(pady=10)
        self.usingExistingKeyButton.pack(pady=10)

    def _signalGenerateNewKey(self):
        electronic_signature = ElectronicSignature()

        keysFolderName = filedialog.askdirectory(title="Введите имя файла для сохранения ключей")
        if not keysFolderName:
            return

        secret_phrase = simpledialog.askstring(
            "Введите парольную фразу для ключей",
            "Парольная фраза",
            show='*'
        )
        if secret_phrase is None:
            return

        electronic_signature.save_keys(pathlib.Path(keysFolderName), secret_phrase)

        fileName = filedialog.askopenfilename(title="Выберите файл, который нужно подписать")
        if not fileName:
            return

        userName = simpledialog.askstring("Введите имя подписывающего", "Имя")
        if userName is None:
            return

        electronic_signature.sign(pathlib.Path(fileName))

        electronicSignatureFileName = filedialog.asksaveasfilename(
            title="Введите имя файла, куда необходимо сохранить подпись?"
        )
        if not electronicSignatureFileName:
            return

        electronic_signature.save_signature(userName, pathlib.Path(electronicSignatureFileName))

        self.destroy()

    def _signalUsingExistingKey(self):
        keysFolderName = filedialog.askdirectory(title="Введите имя файла для откуда взять ключи")
        if not keysFolderName:
            return

        secret_phrase = simpledialog.askstring(
            "Введите парольную фразу для ключей",
            "Парольная фраза",
            show='*'
        )
        if secret_phrase is None:
            return

        electronic_signature = ElectronicSignature()
        try:
            electronic_signature.load_keys(pathlib.Path(keysFolderName), secret_phrase)
        except ValueError as e:
            messagebox.showerror("Ошибка", "Вы ввели некорректный ключ")
            self.destroy()
            return

        fileName = filedialog.askopenfilename(title="Выберите файл")
        if not fileName:
            return

        userName = simpledialog.askstring("Введите имя подписывающего", "Имя")
        if userName is None:
            return

        electronic_signature.sign(pathlib.Path(fileName))

        electronicSignatureFileName = filedialog.asksaveasfilename(
            title="Введите имя файла, куда необходимо сохранить подпись?"
        )
        if not electronicSignatureFileName:
            return

        electronic_signature.save_signature(userName, pathlib.Path(electronicSignatureFileName))
        self.destroy()
