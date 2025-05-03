from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QLabel, QFileDialog, QTableWidget, QTableWidgetItem,
    QLineEdit, QHBoxLayout, QHeaderView
)
import sys
import os
from analyzer import analyze_path

class StaticAnalyzerUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Static Analyzer")
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout()

        self.label = QLabel("Enter path or choose a directory:")
        layout.addWidget(self.label)

        path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        path_layout.addWidget(self.path_input)

        self.choose_button = QPushButton("Browse Folder")
        self.choose_button.clicked.connect(self.choose_folder)
        path_layout.addWidget(self.choose_button)

        layout.addLayout(path_layout)

        self.analyze_button = QPushButton("Analyze")
        self.analyze_button.clicked.connect(self.run_analysis)
        layout.addWidget(self.analyze_button)

        self.total_files_label = QLabel("Total files scanned: 0")
        self.malicious_count_label = QLabel("Malicious files: 0")
        self.safe_count_label = QLabel("Safe files: 0")
        self.error_count_label = QLabel("Error scanning files: 0")
        layout.addWidget(self.total_files_label)
        layout.addWidget(self.malicious_count_label)
        layout.addWidget(self.safe_count_label)
        layout.addWidget(self.error_count_label)

        self.malicious_table = QTableWidget()
        self.malicious_table.setColumnCount(1)
        self.malicious_table.setHorizontalHeaderLabels(["Malicious Files"])
        self.malicious_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        layout.addWidget(self.malicious_table)

        self.safe_table = QTableWidget()
        self.safe_table.setColumnCount(1)
        self.safe_table.setHorizontalHeaderLabels(["Safe Files"])
        self.safe_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        layout.addWidget(self.safe_table)

        self.error_table = QTableWidget()
        self.error_table.setColumnCount(1)
        self.error_table.setHorizontalHeaderLabels(["Files with Errors"])
        self.error_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        layout.addWidget(self.error_table)

        self.setLayout(layout)

    def choose_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder_path:
            self.path_input.setText(folder_path)

    def run_analysis(self):
        folder_path = self.path_input.text()
        if os.path.exists(folder_path):
            malicious_files, safe_files, error_files, scanned_files, _, malicious_count, safe_count, error_count = analyze_path(folder_path)

            self.malicious_table.setRowCount(0)
            self.safe_table.setRowCount(0)
            self.error_table.setRowCount(0)

            self.malicious_table.setRowCount(len(malicious_files))
            for i, file in enumerate(malicious_files):
                self.malicious_table.setItem(i, 0, QTableWidgetItem(os.path.basename(file)))

            self.safe_table.setRowCount(len(safe_files))
            for i, file in enumerate(safe_files):
                self.safe_table.setItem(i, 0, QTableWidgetItem(os.path.basename(file)))

            self.error_table.setRowCount(len(error_files))
            for i, file in enumerate(error_files):
                self.error_table.setItem(i, 0, QTableWidgetItem(os.path.basename(file)))

            self.total_files_label.setText(f"Total files scanned: {scanned_files}")
            self.malicious_count_label.setText(f"Malicious files: {malicious_count}")
            self.safe_count_label.setText(f"Safe files: {safe_count}")
            self.error_count_label.setText(f"Error scanning files: {error_count}")

        else:
            self.malicious_table.setRowCount(1)
            self.malicious_table.setItem(0, 0, QTableWidgetItem("Invalid path."))
            self.safe_table.setRowCount(0)
            self.error_table.setRowCount(0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = StaticAnalyzerUI()
    window.show()
    sys.exit(app.exec_())