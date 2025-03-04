import os
import sys
import string
import pickle
from collections import Counter

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QLabel, QLineEdit, QTextEdit, QRadioButton, QPushButton, 
                           QAction, QFileDialog, QMessageBox, QTreeWidget, 
                           QTreeWidgetItem, QGroupBox, QButtonGroup, QStatusBar,
                           QDialog, QDialogButtonBox, QGridLayout, QTreeView)
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


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About")
        self.resize(400, 300)
        
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("Shift Cipher Cryptosystem")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Version
        version_label = QLabel("Version 1.0")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)
        
        layout.addSpacing(20)
        
        # Developer info
        dev_label = QLabel("Developed by:")
        dev_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(dev_label)
        
        name_label = QLabel("Dorofieiev Danylo")
        name_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(name_label)
        
        email_label = QLabel("Email: danylo.dorofieiev@lnu.edu.ua")
        email_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(email_label)
        
        layout.addSpacing(20)
        
        # Description
        desc_label = QLabel("A cryptographic system for encrypting and decrypting text\n"
                       "using the Shift Cipher (Caesar Cipher) algorithm.\n"
                       "Supports both Latin (English) and Ukrainian alphabets.")
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)
        
        layout.addSpacing(20)
        
        # Close button
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)


class BruteForceDialog(QDialog):
    def __init__(self, results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Brute Force Results")
        self.resize(600, 400)
        
        self.results = results
        self.selected_key = None
        self.selected_text = None
        
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Brute Force Results - Double-click a result to use it")
        header.setStyleSheet("font-size: 14px; font-weight: bold;")
        layout.addWidget(header)
        
        # Results tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Key", "Preview"])
        self.tree.setColumnWidth(0, 50)
        self.tree.setColumnWidth(1, 550)
        
        for key, plaintext in results:
            # Truncate preview if too long
            preview = plaintext[:50] + "..." if len(plaintext) > 50 else plaintext
            item = QTreeWidgetItem([str(key), preview])
            self.tree.addTopLevelItem(item)
        
        self.tree.itemDoubleClicked.connect(self.item_double_clicked)
        layout.addWidget(self.tree)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def item_double_clicked(self, item, column):
        key = int(item.text(0))
        self.selected_key = key
        self.selected_text = self.results[key][1]
        self.accept()


class FrequencyAnalysisDialog(QDialog):
    def __init__(self, text_freq, std_freq, alphabet, language, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Frequency Analysis - {language}")
        self.resize(800, 600)
        
        self.text_freq = text_freq
        self.std_freq = std_freq
        self.alphabet = alphabet
        self.language = language
        
        layout = QVBoxLayout()
        
        # Create the plot
        figure = plt.figure(figsize=(10, 6))
        canvas = FigureCanvas(figure)
        ax = figure.add_subplot(111)
        
        # Get all characters from the alphabet (excluding space for better visualization)
        chars = [char for char in alphabet if char != ' ']
        
        # Get frequency values for each character
        text_freqs = [text_freq.get(char, 0) for char in chars]
        std_freqs = [std_freq.get(char, 0) for char in chars]
        
        # Set up bar positions
        x = np.arange(len(chars))
        width = 0.35
        
        # Create bars
        ax.bar(x - width/2, text_freqs, width, label='Current Text')
        ax.bar(x + width/2, std_freqs, width, label='Standard')
        
        # Add labels and title
        ax.set_xlabel('Characters')
        ax.set_ylabel('Frequency')
        ax.set_title(f'Character Frequency Analysis - {language}')
        ax.set_xticks(x)
        ax.set_xticklabels(chars)
        ax.legend()
        
        layout.addWidget(canvas)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        save_button = QPushButton("Save as Standard")
        save_button.clicked.connect(self.save_as_standard)
        button_layout.addWidget(save_button)
        
        button_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def save_as_standard(self):
        if self.language == "English":
            filename = 'english_freq.pkl'
        else:  # Ukrainian
            filename = 'ukrainian_freq.pkl'
        
        with open(filename, 'wb') as f:
            pickle.dump(self.text_freq, f)
        
        QMessageBox.information(self, "Success", f"Frequency table saved as standard for {self.language}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.cipher = ShiftCipher()
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
        valid, result = self.cipher.validate_key(key, alphabet)
        
        if not valid:
            QMessageBox.critical(self, "Error", result)
            return
        
        encrypted_text = self.cipher.encrypt(text, result, alphabet)
        self.text_edit.setText(encrypted_text)
        
        self.set_modified(True)
        self.status_bar.showMessage(f"Text encrypted with key: {key}")
    
    def decrypt_text(self):
        """Decrypt the text in the text edit"""
        text = self.text_edit.toPlainText()
        key = self.key_input.text()
        
        # Validate key
        alphabet = self.get_current_alphabet()
        valid, result = self.cipher.validate_key(key, alphabet)
        
        if not valid:
            QMessageBox.critical(self, "Error", result)
            return
        
        decrypted_text = self.cipher.decrypt(text, result, alphabet)
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
    
    def show_about(self):
        """Show information about the developer"""
        dialog = AboutDialog(self)
        dialog.exec_()


def run_tests():
    """Run tests on the cipher implementation"""
    print("Running tests...")
    
    cipher = ShiftCipher()
    
    # Test English encryption/decryption
    original = "hello world"
    key = 3
    encrypted = cipher.encrypt(original, key, cipher.latin_alphabet)
    decrypted = cipher.decrypt(encrypted, key, cipher.latin_alphabet)
    
    print(f"Original: {original}")
    print(f"Encrypted (key={key}): {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Test passed: {original == decrypted}")
    
    # Test Ukrainian encryption/decryption
    original = "привіт світ"
    key = 5
    encrypted = cipher.encrypt(original, key, cipher.ukrainian_alphabet)
    decrypted = cipher.decrypt(encrypted, key, cipher.ukrainian_alphabet)
    
    print(f"Original: {original}")
    print(f"Encrypted (key={key}): {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Test passed: {original == decrypted}")
    
    # Test brute force
    ciphertext = "khoor zruog"
    results = cipher.brute_force_attack(ciphertext, cipher.latin_alphabet)
    found = False
    for key, plaintext in results:
        if plaintext == "hello world":
            print(f"Brute force successful! Found key: {key}")
            found = True
            break
    
    print(f"Brute force test passed: {found}")
    
    # Test binary encryption/decryption
    binary_cipher = BinaryShiftCipher()
    test_file = "test_file.txt"
    encrypted_file = "test_file.enc"
    decrypted_file = "test_file_decrypted.txt"
    
    # Create a test file
    with open(test_file, 'wb') as f:
        f.write(b"This is a test binary file.")
    
    # Encrypt and decrypt
    binary_cipher.encrypt_file(test_file, encrypted_file, 42)
    binary_cipher.decrypt_file(encrypted_file, decrypted_file, 42)
    
    # Check if the decrypted file matches the original
    with open(test_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
        original_data = f1.read()
        decrypted_data = f2.read()
        print(f"Binary test passed: {original_data == decrypted_data}")
    
    # Clean up test files
    for file in [test_file, encrypted_file, decrypted_file]:
        if os.path.exists(file):
            os.remove(file)
    
    print("Tests completed.")


if __name__ == "__main__":
    # Run tests
    run_tests()
    
    # Start the GUI application
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern style
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())