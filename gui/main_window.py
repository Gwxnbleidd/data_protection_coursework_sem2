import pathlib

from PyQt6.QtWidgets import (QPushButton, QVBoxLayout, QMainWindow, 
                             QWidget, QFileDialog, QMessageBox)
from PyQt6.QtCore import QSize

from core.electronic_signature import ElectronicSignature
from .choice_key_window import ChoiseKeyWindow

class MainWindow(QMainWindow):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.checkSignatureButton = QPushButton("Проверить документ")
        self.signSignatureButton = QPushButton("Подписать документ")

        self.setWindowTitle("Электронная подпись")
        self.setFixedSize(QSize(400, 400))

        vBoxLayout = QVBoxLayout()
        vBoxLayout.addWidget(self.checkSignatureButton)
        vBoxLayout.addWidget(self.signSignatureButton)

        widget = QWidget()
        widget.setLayout(vBoxLayout)

        self.setCentralWidget(widget)

        # set signals
        self.signSignatureButton.pressed.connect(self._signalSignDocument)
        self.checkSignatureButton.pressed.connect(self._signalCheckSignatureDocument)

    def _signalSignDocument(self):
        self.choiseKeyWindow = ChoiseKeyWindow()
        self.choiseKeyWindow.show()

    def _signalCheckSignatureDocument(self):
        fileName, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        signatureFileName, _ = QFileDialog.getOpenFileName(self, "Укажите путь к файлу с подписью")

        electronic_signature = ElectronicSignature()  
        verifyStatus = electronic_signature.verify(pathlib.Path(fileName), pathlib.Path(signatureFileName))
        
        message = (
            f"Файл {fileName.title()}, был подписан пользователем {verifyStatus.user_name}" 
            if verifyStatus.status
            else f"Файл {fileName.title()}, был кем-то изменен, после подписания пользователем {verifyStatus.user_name}")
        
        self.signatureVerifyMessageBox = QMessageBox()
        self.signatureVerifyMessageBox.setWindowTitle("Информация")
        self.signatureVerifyMessageBox.setText(message)
        self.signatureVerifyMessageBox.show()


