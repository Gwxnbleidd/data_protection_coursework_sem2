import sys
import os

# sys.path.append(os.getcwd())

from core.electronic_signature import ElectronicSignature

from PyQt6.QtWidgets import QApplication

from gui.main_window import MainWindow

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()