import os
import sys
import string
import pickle
from collections import Counter

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QRadioButton, QPushButton,
    QAction, QFileDialog, QMessageBox, QTreeWidget,
    QTreeWidgetItem, QGroupBox, QButtonGroup, QStatusBar,
    QDialog, QDialogButtonBox, QGridLayout, QListWidget, QListWidgetItem  
)

from PyQt5.QtPrintSupport import QPrintDialog, QPrinter
from PyQt5.QtGui import QIcon, QFont, QTextCursor
from PyQt5.QtCore import Qt, QFileInfo, QDir

import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import numpy as np


class ShiftCipher:
    def __init__(self):
        # Latin alphabet (English) with space
        self.latin_alphabet = ' ' + string.ascii_lowercase
        # Ukrainian alphabet with space
        self.ukrainian_alphabet = ' абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'

    def validate_key(self, key, alphabet):
        """Validate that the key is a valid integer for the given alphabet"""
        try:
            key = int(key)
            if key < 0 or key >= len(alphabet):
                return False, f"Key must be between 0 and {len(alphabet) - 1}"
            return True, key
        except ValueError:
            return False, "Key must be an integer"

    def encrypt(self, text, key, alphabet):
        """Encrypt text using the shift cipher with the specified key and alphabet"""
        result = ""
        for char in text.lower():
            if char in alphabet:
                # Find the position of the character in the alphabet
                pos = alphabet.find(char)
                # Apply the shift
                new_pos = (pos + key) % len(alphabet)
                # Get the new character
                result += alphabet[new_pos]
            else:
                # Keep characters not in the alphabet unchanged
                result += char
        return result

    def decrypt(self, text, key, alphabet):
        """Decrypt text using the shift cipher with the specified key and alphabet"""
        # Decryption is just encryption with the negative key
        return self.encrypt(text, -key, alphabet)

    def brute_force_attack(self, ciphertext, alphabet):
        """Try all possible keys to decrypt the ciphertext"""
        results = []
        for key in range(len(alphabet)):
            plaintext = self.encrypt(ciphertext, -key, alphabet)
            results.append((key, plaintext))
        return results

    def frequency_analysis(self, text, alphabet):
        """Perform frequency analysis on the given text"""
        # Count occurrences of each character in the alphabet
        freq = Counter(char for char in text.lower() if char in alphabet)
        # Normalize to get frequencies
        total = sum(freq.values())
        if total == 0:
            return {}
        return {char: count / total for char, count in freq.items()}


class TrithemiusCipher:
    def __init__(self):
        # Latin alphabet (English) with space
        self.latin_alphabet = ' ' + string.ascii_lowercase
        # Ukrainian alphabet with space
        self.ukrainian_alphabet = ' абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'

    def validate_key(self, key, alphabet):
        """Validate that the key is valid for the given alphabet"""
        if isinstance(key, tuple):
            if len(key) == 2:  # Linear equation coefficients (A, B)
                return True, key
            elif len(key) == 3:  # Quadratic equation coefficients (A, B, C)
                return True, key
        elif isinstance(key, str):  # Keyword (haslo)
            return True, key
        return False, "Invalid key format. Key must be a tuple (A, B) or (A, B, C) for equations, or a string for keyword."

    def calculate_shift(self, p, key):
        """Calculate the shift based on the position p and the key"""
        if isinstance(key, tuple):
            if len(key) == 2:  # Linear equation: k = A*p + B
                A, B = key
                return A * p + B
            elif len(key) == 3:  # Quadratic equation: k = A*p^2 + B*p + C
                A, B, C = key
                return A * p**2 + B * p + C
        elif isinstance(key, str):  # Keyword (haslo)
            # The shift is determined by the position of the character in the keyword
            return ord(key[p % len(key)]) - ord('a')
        return 0

    def encrypt(self, text, key, alphabet):
        """Encrypt text using the Trithemius cipher with the specified key and alphabet"""
        result = ""
        for p, char in enumerate(text.lower()):
            if char in alphabet:
                # Find the position of the character in the alphabet
                pos = alphabet.find(char)
                # Calculate the shift
                shift = self.calculate_shift(p, key)
                # Apply the shift
                new_pos = (pos + shift) % len(alphabet)
                # Get the new character
                result += alphabet[new_pos]
            else:
                # Keep characters not in the alphabet unchanged
                result += char
        return result

    def decrypt(self, text, key, alphabet):
        """Decrypt text using the Trithemius cipher with the specified key and alphabet"""
        result = ""
        for p, char in enumerate(text.lower()):
            if char in alphabet:
                # Find the position of the character in the alphabet
                pos = alphabet.find(char)
                # Calculate the shift
                shift = self.calculate_shift(p, key)
                # Apply the negative shift
                new_pos = (pos - shift) % len(alphabet)
                # Get the new character
                result += alphabet[new_pos]
            else:
                # Keep characters not in the alphabet unchanged
                result += char
        return result

    def active_attack(self, plaintext, ciphertext, alphabet):
        """Perform an active attack to find the key using a pair of plaintext and ciphertext"""
        if len(plaintext) != len(ciphertext):
            return None, "Plaintext and ciphertext must be of the same length"

        # Determine the type of key (linear, quadratic, or keyword)
        # For simplicity, assume linear key (A, B)
        A = 1  # Default value
        B = 0  # Default value

        # Solve for A and B using the first two characters
        try:
            p1 = alphabet.find(plaintext[0])
            y1 = alphabet.find(ciphertext[0])
            p2 = alphabet.find(plaintext[1])
            y2 = alphabet.find(ciphertext[1])

            # Solve the system of equations:
            # y1 = (p1 + A*p1 + B) mod n
            # y2 = (p2 + A*p2 + B) mod n
            n = len(alphabet)
            A = (y2 - y1 - p2 + p1) * pow(p2 - p1, -1, n) % n
            B = (y1 - A * p1) % n

            return (A, B), "Linear key found"
        except Exception as e:
            return None, f"Failed to find key: {str(e)}"


class BinaryShiftCipher:
    def __init__(self):
        self.shift_cipher = ShiftCipher()

    def encrypt_file(self, input_file, output_file, key):
        """Encrypt binary data using a simple XOR operation with the key"""
        try:
            with open(input_file, 'rb') as f_in:
                data = f_in.read()

            # Use the key as a byte to XOR with each byte in the file
            key_byte = key % 256
            encrypted_data = bytearray(b ^ key_byte for b in data)

            with open(output_file, 'wb') as f_out:
                f_out.write(encrypted_data)

            return True, "File encrypted successfully"
        except Exception as e:
            return False, f"Error encrypting file: {str(e)}"

    def decrypt_file(self, input_file, output_file, key):
        """Decrypt binary data - XOR operation is its own inverse with the same key"""
        return self.encrypt_file(input_file, output_file, key)


class BruteForceDialog(QDialog):
    def __init__(self, results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Brute Force Results")
        self.resize(600, 400)

        layout = QVBoxLayout()
        self.results_list = QListWidget()  # Використовуємо QListWidget
        
        for key, plaintext in results:
            item = QListWidgetItem(f"Key {key}: {plaintext[:50]}...")
            item.setData(Qt.UserRole, (key, plaintext))
            self.results_list.addItem(item)
        
        self.results_list.itemDoubleClicked.connect(self.item_selected)
        layout.addWidget(self.results_list)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)

    def item_selected(self, item):
        self.selected_key, self.selected_text = item.data(Qt.UserRole)
        self.accept()


class FrequencyAnalysisDialog(QDialog):
    def __init__(self, current_freq, std_freq, alphabet, language, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Frequency Analysis ({language})")
        self.resize(800, 600)

        # Create a figure and axis
        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        self.ax = self.figure.add_subplot(111)

        # Plot data
        chars = [char for char in alphabet if char != ' ']  # Exclude space for better visualization
        x = np.arange(len(chars))
        width = 0.35

        # Get frequencies for characters in the same order as chars list
        current_values = [current_freq.get(char, 0) for char in chars]
        std_values = [std_freq.get(char, 0) for char in chars]

        # Create bars
        self.ax.bar(x - width/2, current_values, width, label='Current Text')
        self.ax.bar(x + width/2, std_values, width, label='Standard')

        # Formatting
        self.ax.set_xticks(x)
        self.ax.set_xticklabels(chars)
        self.ax.set_xlabel('Characters')
        self.ax.set_ylabel('Frequency')
        self.ax.set_title('Character Frequency Comparison')
        self.ax.legend()
        plt.xticks(rotation=45)
        self.figure.tight_layout()

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.canvas)
        
        # Close button
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About")
        self.resize(400, 300)
        
        layout = QVBoxLayout()
        
        info_label = QLabel(
            "<h2>Crypto System</h2>"
            "<p>Version 2.0</p>"
            "<p>Developed by Danylo Dorofieiev\nEmail: danylo.dorofieiev@lnu.edu.ua</p>"
            "<p>Система шифрування з підтримкою алгоритмів Цезаря та Тритеміуса</p>"
            "<p>© 2024 Всі права захищені</p>"
        )
        info_label.setWordWrap(True)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        
        layout.addWidget(info_label)
        layout.addWidget(buttons)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cipher = ShiftCipher()
        self.trithemius_cipher = TrithemiusCipher()
        self.binary_cipher = BinaryShiftCipher()

        self.current_file = None
        self.is_modified = False

        self.init_ui()

        # Standard frequency tables
        self.english_freq_table = self.load_or_create_freq_table('english_freq.pkl', self.cipher.latin_alphabet)
        self.ukrainian_freq_table = self.load_or_create_freq_table('ukrainian_freq.pkl', self.cipher.ukrainian_alphabet)

    def load_or_create_freq_table(self, filename, alphabet):
        """Load frequency table from file or create a new empty one"""
        try:
            with open(filename, 'rb') as f:
                return pickle.load(f)
        except:
            return {char: 0.0 for char in alphabet}

    def init_ui(self):
        self.setWindowTitle("Shift Cipher Cryptosystem")
        self.resize(800, 600)

        # Create menu bar
        self.create_menu_bar()

        # Create toolbar
        self.create_toolbar()

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Create main layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        # Language and key controls
        control_layout = QHBoxLayout()

        # Language selection
        lang_group = QGroupBox("Language")
        lang_layout = QHBoxLayout()

        self.english_radio = QRadioButton("English")
        self.english_radio.setChecked(True)
        self.ukrainian_radio = QRadioButton("Ukrainian")

        lang_layout.addWidget(self.english_radio)
        lang_layout.addWidget(self.ukrainian_radio)
        lang_group.setLayout(lang_layout)

        control_layout.addWidget(lang_group)

        # Key input
        key_group = QGroupBox("Key")
        key_layout = QHBoxLayout()

        self.key_input = QLineEdit("3")
        self.key_input.setMaximumWidth(100)

        key_layout.addWidget(self.key_input)
        key_group.setLayout(key_layout)

        control_layout.addWidget(key_group)
        control_layout.addStretch()

        main_layout.addLayout(control_layout)

        # Cipher selection
        cipher_group = QGroupBox("Cipher")
        cipher_layout = QHBoxLayout()

        self.caesar_radio = QRadioButton("Caesar")
        self.caesar_radio.setChecked(True)
        self.trithemius_radio = QRadioButton("Trithemius")

        cipher_layout.addWidget(self.caesar_radio)
        cipher_layout.addWidget(self.trithemius_radio)
        cipher_group.setLayout(cipher_layout)

        main_layout.addWidget(cipher_group)

        # Text area
        self.text_edit = QTextEdit()
        self.text_edit.textChanged.connect(lambda: self.set_modified(True))
        main_layout.addWidget(self.text_edit)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def create_menu_bar(self):
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        new_action = QAction("&New", self)
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self.new_file)
        file_menu.addAction(new_action)

        open_action = QAction("&Open", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)

        save_action = QAction("&Save", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_file)
        file_menu.addAction(save_action)

        save_as_action = QAction("Save &As", self)
        save_as_action.triggered.connect(self.save_as)
        file_menu.addAction(save_as_action)

        file_menu.addSeparator()

        print_action = QAction("&Print", self)
        print_action.triggered.connect(self.print_file)
        file_menu.addAction(print_action)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Cipher menu
        cipher_menu = menubar.addMenu("&Cipher")

        encrypt_action = QAction("&Encrypt", self)
        encrypt_action.triggered.connect(self.encrypt_text)
        cipher_menu.addAction(encrypt_action)

        decrypt_action = QAction("&Decrypt", self)
        decrypt_action.triggered.connect(self.decrypt_text)
        cipher_menu.addAction(decrypt_action)

        cipher_menu.addSeparator()

        binary_encrypt_action = QAction("Binary &Encrypt", self)
        binary_encrypt_action.triggered.connect(self.encrypt_binary)
        cipher_menu.addAction(binary_encrypt_action)

        binary_decrypt_action = QAction("Binary &Decrypt", self)
        binary_decrypt_action.triggered.connect(self.decrypt_binary)
        cipher_menu.addAction(binary_decrypt_action)

        cipher_menu.addSeparator()

        brute_force_action = QAction("&Brute Force Attack", self)
        brute_force_action.triggered.connect(self.brute_force)
        cipher_menu.addAction(brute_force_action)

        frequency_action = QAction("&Frequency Analysis", self)
        frequency_action.triggered.connect(self.show_frequency_analysis)
        cipher_menu.addAction(frequency_action)

        active_attack_action = QAction("&Active Attack", self)
        active_attack_action.triggered.connect(self.active_attack)
        cipher_menu.addAction(active_attack_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_toolbar(self):
        toolbar = self.addToolBar("Main Toolbar")
        toolbar.setMovable(False)

        new_action = QAction("New", self)
        new_action.triggered.connect(self.new_file)
        toolbar.addAction(new_action)

        open_action = QAction("Open", self)
        open_action.triggered.connect(self.open_file)
        toolbar.addAction(open_action)

        save_action = QAction("Save", self)
        save_action.triggered.connect(self.save_file)
        toolbar.addAction(save_action)

        toolbar.addSeparator()

        encrypt_action = QAction("Encrypt", self)
        encrypt_action.triggered.connect(self.encrypt_text)
        toolbar.addAction(encrypt_action)

        decrypt_action = QAction("Decrypt", self)
        decrypt_action.triggered.connect(self.decrypt_text)
        toolbar.addAction(decrypt_action)

        toolbar.addSeparator()

        brute_force_action = QAction("Brute Force", self)
        brute_force_action.triggered.connect(self.brute_force)
        toolbar.addAction(brute_force_action)

        frequency_action = QAction("Frequency", self)
        frequency_action.triggered.connect(self.show_frequency_analysis)
        toolbar.addAction(frequency_action)

    def set_modified(self, value):
        self.is_modified = value
        if value:
            self.setWindowTitle("Shift Cipher Cryptosystem *")
        else:
            self.setWindowTitle("Shift Cipher Cryptosystem")

    def closeEvent(self, event):
        if self.is_modified:
            reply = QMessageBox.question(self, "Unsaved Changes",
                                       "You have unsaved changes. Exit anyway?",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.No:
                event.ignore()
                return

        event.accept()

    def new_file(self):
        if self.is_modified:
            reply = QMessageBox.question(self, "Unsaved Changes",
                                       "You have unsaved changes. Create new file anyway?",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.No:
                return

        self.text_edit.clear()
        self.current_file = None
        self.set_modified(False)
        self.status_bar.showMessage("New file created")

    def open_file(self):
        if self.is_modified:
            reply = QMessageBox.question(self, "Unsaved Changes",
                                       "You have unsaved changes. Open another file anyway?",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.No:
                return

        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Open File", "",
                                                  "Text Files (*.txt);;All Files (*)",
                                                  options=options)

        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    self.text_edit.setText(content)
                    self.current_file = file_path
                    self.set_modified(False)
                    self.status_bar.showMessage(f"Opened: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not open file: {str(e)}")

    def save_file(self):
        if not self.current_file:
            return self.save_as()

        try:
            with open(self.current_file, 'w', encoding='utf-8') as file:
                content = self.text_edit.toPlainText()
                file.write(content)
                self.set_modified(False)
                self.status_bar.showMessage(f"Saved: {self.current_file}")
                return True
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not save file: {str(e)}")
            return False

    def save_as(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save As", "",
                                                 "Text Files (*.txt);;All Files (*)",
                                                 options=options)

        if file_path:
            self.current_file = file_path
            return self.save_file()
        return False

    def print_file(self):
        """Print the current document"""
        printer = QPrinter()
        print_dialog = QPrintDialog(printer, self)
        if print_dialog.exec_() == QPrintDialog.Accepted:
            self.text_edit.print_(printer)

    def get_current_alphabet(self):
        """Get the alphabet for the selected language"""
        if self.english_radio.isChecked():
            return self.cipher.latin_alphabet
        else:  # Ukrainian
            return self.cipher.ukrainian_alphabet

    def get_language_name(self):
        """Get the name of the selected language"""
        if self.english_radio.isChecked():
            return "English"
        else:
            return "Ukrainian"

    def encrypt_text(self):
        """Encrypt the text in the text edit"""
        text = self.text_edit.toPlainText()
        key = self.key_input.text()

        # Validate key
        alphabet = self.get_current_alphabet()

        if self.caesar_radio.isChecked():
            valid, result = self.cipher.validate_key(key, alphabet)
            if not valid:
                QMessageBox.critical(self, "Error", result)
                return
            encrypted_text = self.cipher.encrypt(text, result, alphabet)
        else:  # Trithemius cipher
            try:
                if '(' in key and ')' in key:
                    # Parse tuple for linear or quadratic equation
                    key = eval(key)
                valid, result = self.trithemius_cipher.validate_key(key, alphabet)
                if not valid:
                    QMessageBox.critical(self, "Error", result)
                    return
                encrypted_text = self.trithemius_cipher.encrypt(text, result, alphabet)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Invalid key format: {str(e)}")
                return

        self.text_edit.setText(encrypted_text)
        self.set_modified(True)
        self.status_bar.showMessage(f"Text encrypted with key: {key}")

    def decrypt_text(self):
        """Decrypt the text in the text edit"""
        text = self.text_edit.toPlainText()
        key = self.key_input.text()

        # Validate key
        alphabet = self.get_current_alphabet()

        if self.caesar_radio.isChecked():
            valid, result = self.cipher.validate_key(key, alphabet)
            if not valid:
                QMessageBox.critical(self, "Error", result)
                return
            decrypted_text = self.cipher.decrypt(text, result, alphabet)
        else:  # Trithemius cipher
            try:
                if '(' in key and ')' in key:
                    # Parse tuple for linear or quadratic equation
                    key = eval(key)
                valid, result = self.trithemius_cipher.validate_key(key, alphabet)
                if not valid:
                    QMessageBox.critical(self, "Error", result)
                    return
                decrypted_text = self.trithemius_cipher.decrypt(text, result, alphabet)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Invalid key format: {str(e)}")
                return

        self.text_edit.setText(decrypted_text)
        self.set_modified(True)
        self.status_bar.showMessage(f"Text decrypted with key: {key}")

    def encrypt_binary(self):
        """Encrypt a binary file"""
        if self.is_modified:
            reply = QMessageBox.question(self, "Unsaved Changes",
                                       "You have unsaved changes. Continue anyway?",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.No:
                return

        options = QFileDialog.Options()
        input_file, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt", "",
                                                  "All Files (*)", options=options)

        if not input_file:
            return

        output_file, _ = QFileDialog.getSaveFileName(self, "Save encrypted file", "",
                                                   "Encrypted Files (*.enc);;All Files (*)",
                                                   options=options)

        if not output_file:
            return

        key = self.key_input.text()
        try:
            key = int(key)
        except ValueError:
            QMessageBox.critical(self, "Error", "Key must be an integer")
            return

        success, message = self.binary_cipher.encrypt_file(input_file, output_file, key)
        if success:
            QMessageBox.information(self, "Success", message)
            self.status_bar.showMessage(f"File encrypted: {os.path.basename(input_file)} -> {os.path.basename(output_file)}")
        else:
            QMessageBox.critical(self, "Error", message)

    def decrypt_binary(self):
        """Decrypt a binary file"""
        if self.is_modified:
            reply = QMessageBox.question(self, "Unsaved Changes",
                                       "You have unsaved changes. Continue anyway?",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.No:
                return

        options = QFileDialog.Options()
        input_file, _ = QFileDialog.getOpenFileName(self, "Select file to decrypt", "",
                                                  "Encrypted Files (*.enc);;All Files (*)",
                                                  options=options)

        if not input_file:
            return

        output_file, _ = QFileDialog.getSaveFileName(self, "Save decrypted file", "",
                                                   "All Files (*)", options=options)

        if not output_file:
            return

        key = self.key_input.text()
        try:
            key = int(key)
        except ValueError:
            QMessageBox.critical(self, "Error", "Key must be an integer")
            return

        success, message = self.binary_cipher.decrypt_file(input_file, output_file, key)
        if success:
            QMessageBox.information(self, "Success", message)
            self.status_bar.showMessage(f"File decrypted: {os.path.basename(input_file)} -> {os.path.basename(output_file)}")
        else:
            QMessageBox.critical(self, "Error", message)

    def brute_force(self):
        """Perform a brute force attack on the ciphertext"""
        text = self.text_edit.toPlainText()
        if not text:
            QMessageBox.critical(self, "Error", "No text to attack")
            return

        alphabet = self.get_current_alphabet()
        results = self.cipher.brute_force_attack(text, alphabet)

        dialog = BruteForceDialog(results, self)
        if dialog.exec_() == QDialog.Accepted and dialog.selected_key is not None:
            self.text_edit.setText(dialog.selected_text)
            self.key_input.setText(str(dialog.selected_key))
            self.set_modified(True)

    def show_frequency_analysis(self):
        """Show frequency analysis of the text"""
        text = self.text_edit.toPlainText()
        if not text:
            QMessageBox.critical(self, "Error", "No text to analyze")
            return

        language = self.get_language_name()
        alphabet = self.get_current_alphabet()
        freq = self.cipher.frequency_analysis(text, alphabet)

        # Get standard frequency table for comparison
        if language == "English":
            std_freq = self.english_freq_table
        else:  # Ukrainian
            std_freq = self.ukrainian_freq_table

        dialog = FrequencyAnalysisDialog(freq, std_freq, alphabet, language, self)
        dialog.exec_()

    def active_attack(self):
        """Perform an active attack on the Trithemius cipher"""
        if not self.trithemius_radio.isChecked():
            QMessageBox.critical(self, "Error", "Active attack is only available for the Trithemius cipher")
            return

        # Get the plaintext and ciphertext
        plaintext = self.text_edit.toPlainText()
        if not plaintext:
            QMessageBox.critical(self, "Error", "No plaintext available")
            return

        ciphertext = self.text_edit.toPlainText()
        if not ciphertext:
            QMessageBox.critical(self, "Error", "No ciphertext available")
            return

        # Get the alphabet
        alphabet = self.get_current_alphabet()

        # Perform the active attack
        key, message = self.trithemius_cipher.active_attack(plaintext, ciphertext, alphabet)
        if key is None:
            QMessageBox.critical(self, "Error", message)
            return

        # Display the result
        QMessageBox.information(self, "Active Attack Result", f"Key found: {key}\n{message}")
        self.key_input.setText(str(key))
        self.status_bar.showMessage(f"Active attack successful. Key: {key}")

    def show_about(self):
        """Show information about the developer"""
        dialog = AboutDialog(self)
        dialog.exec_()


if __name__ == "__main__":
    # Start the GUI application
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern style
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())