import pathlib

from PyQt6.QtWidgets import (QWidget, QPushButton, 
                             QVBoxLayout, QFileDialog, QInputDialog, QMessageBox)

from core.electronic_signature import ElectronicSignature

class ChoiseKeyWindow(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self.generateNewKeyButton = QPushButton("Создать новые ключи")
        self.usingExistingKeyButton = QPushButton("Использовать существующие ключи")

        vBoxLayout = QVBoxLayout()
        vBoxLayout.addWidget(self.generateNewKeyButton)
        vBoxLayout.addWidget(self.usingExistingKeyButton)

        self.setLayout(vBoxLayout)

        self.generateNewKeyButton.pressed.connect(self._signalGenerateNewKey)
        self.usingExistingKeyButton.pressed.connect(self._signalUsingExistingKey)

    def _signalGenerateNewKey(self):
        keySize, _ = QInputDialog.getText(self, "Введите размер ключа", "Размер ключа")

        fileName, _ = QFileDialog.getOpenFileName(self, "Выберите файл")

        userName, _ = QInputDialog.getText(self, "Введите имя подписывающего", "Имя")
  
        electronic_signature = ElectronicSignature(int(keySize))  
        electronic_signature.sign(pathlib.Path(fileName))
        
        electronicSignatureFileName, _ = QFileDialog.getSaveFileName(self, "Введите имя файла, куда необходимо сохранить подпись?")
        electronic_signature.save_signature(userName, pathlib.Path(electronicSignatureFileName))

        keysFolderName = QFileDialog.getExistingDirectory(self, "Введите имя файла для сохранения ключей")
        electronic_signature.save_keys(pathlib.Path(keysFolderName))
        self.close()

    def _signalUsingExistingKey(self):
        keysFolderName = QFileDialog.getExistingDirectory(self, "Введите имя файла для откуда взять ключи")
        electronic_signature = ElectronicSignature()

        electronic_signature.load_keys(pathlib.Path(keysFolderName))


        fileName, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        userName, _ = QInputDialog.getText(self, "Введите имя подписывающего", "Имя")

        electronic_signature.sign(pathlib.Path(fileName))

        electronicSignatureFileName, _ = QFileDialog.getSaveFileName(self, "Введите имя файла, куда необходимо сохранить подпись?")
        electronic_signature.save_signature(userName, pathlib.Path(electronicSignatureFileName))
        self.close()
