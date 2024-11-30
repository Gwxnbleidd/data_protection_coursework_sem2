import pathlib

from PyQt6.QtWidgets import (QWidget, QPushButton, 
                             QVBoxLayout, QFileDialog, QInputDialog, QMessageBox)

from core.electronic_signature import ElectronicSignature
from core.arc4_encoder import ARC4Encoder
from core.arc4_decoder import ARC4Decoder

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
        print(f'{electronic_signature.private_key=}')
        print(f'{electronic_signature.public_key=}')
        
        electronicSignatureFileName, _ = QFileDialog.getSaveFileName(self, "Введите имя файла, куда необходимо сохранить подпись?")
        electronic_signature.save_signature(userName, pathlib.Path(electronicSignatureFileName))

        keysFolderName = QFileDialog.getExistingDirectory(self, "Введите имя файла для сохранения ключей")
        key, _ = QInputDialog.getText(self, "Введите ключ для шифрования приватного ключа", "Ключ")
        electronic_signature.set_encoder(ARC4Encoder(key=key))
        electronic_signature.save_keys(pathlib.Path(keysFolderName))
        self.close()

    def _signalUsingExistingKey(self):
        keysFolderName = QFileDialog.getExistingDirectory(self, "Введите имя файла для откуда взять ключи")
        key, _ = QInputDialog.getText(self, "Введите ключ для расшифрования приватного ключа", "Ключ")
        electronic_signature = ElectronicSignature()  
        electronic_signature.set_decoder(ARC4Decoder(key=key))

        print(f'{electronic_signature.private_key=}')
        print(f'{electronic_signature.public_key=}')

        statusLoadKeys = electronic_signature.load_keys(pathlib.Path(keysFolderName))
        if not statusLoadKeys:
            self.invalidPrivateKeyMessageBox = QMessageBox()
            self.invalidPrivateKeyMessageBox.setWindowTitle("Ошибка")
            self.invalidPrivateKeyMessageBox.setText("Вы ввели некорректный ключ")
            self.invalidPrivateKeyMessageBox.show()
            self.close()
            return
        
        fileName, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        userName, _ = QInputDialog.getText(self, "Введите имя подписывающего", "Имя")

        electronic_signature.sign(pathlib.Path(fileName))
        
        electronicSignatureFileName, _ = QFileDialog.getSaveFileName(self, "Введите имя файла, куда необходимо сохранить подпись?")
        electronic_signature.save_signature(userName, pathlib.Path(electronicSignatureFileName))
        self.close()
