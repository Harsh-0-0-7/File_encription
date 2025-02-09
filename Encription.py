import os
import sys
import json
import base64
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path
import tempfile
import shutil
import platform
import ctypes
import threading
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pystray
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Security parameters
PBKDF2_ITERATIONS = 600000
SALT_SIZE = 32
MIN_PASSWORD_LENGTH = 8
RECOVERY_CODE_LENGTH = 16

class SecureVault:
    def __init__(self, folder_path):
        self.folder_path = Path(folder_path).resolve()
        self.vault_path = self.folder_path.parent / f".#{self.folder_path.name}.vault"
        self.lock_file = self.vault_path.with_suffix('.lock')
        self.metadata_file = self.vault_path.with_suffix('.meta')
        self.key = None
        self.temp_dir = None

    def _derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _generate_recovery_code(self):
        return base64.b32encode(os.urandom(10)).decode()[:RECOVERY_CODE_LENGTH]

    def lock(self, password, keep_decrypted=False):
        if not password or len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

        # Generate security elements
        salt = os.urandom(SALT_SIZE)
        key = self._derive_key(password, salt)
        recovery_code = self._generate_recovery_code()
        recovery_salt = os.urandom(SALT_SIZE)
        recovery_key = self._derive_key(recovery_code, recovery_salt)

        fernet = Fernet(key)

        # Create vault
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Copy contents if keeping decrypted
            if keep_decrypted:
                decrypted_path = self.folder_path.parent / f"{self.folder_path.name}_decrypted"
                shutil.copytree(self.folder_path, decrypted_path)

            # Encrypt folder contents
            with open(self.vault_path, 'wb') as vault:
                vault.write(salt)
                directory_structure = []

                for root, dirs, files in os.walk(self.folder_path):
                    for name in dirs + files:
                        path = Path(root) / name
                        relative_path = path.relative_to(self.folder_path)
                        directory_structure.append(str(relative_path))

                encrypted_structure = fernet.encrypt(json.dumps(directory_structure).encode())
                vault.write(encrypted_structure + b'\nSTRUCTURE_END\n')

                for item in directory_structure:
                    item_path = self.folder_path / item
                    if item_path.is_file():
                        with open(item_path, 'rb') as f:
                            data = f.read()
                        encrypted = fernet.encrypt(data)
                        vault.write(encrypted + b'\nFILE_END\n')

            # Save metadata
            metadata = {
                'salt': base64.b64encode(salt).decode(),
                'recovery_salt': base64.b64encode(recovery_salt).decode(),
                'recovery_hash': hashlib.sha3_256(recovery_key).hexdigest()
            }

            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f)

            # Save verification hash
            with open(self.lock_file, 'wb') as f:
                f.write(hashlib.sha3_256(key).digest())

            if not keep_decrypted:
                shutil.rmtree(self.folder_path)

        return recovery_code

    def unlock(self, password, keep_encrypted=False):
        if not self.lock_file.exists() or not self.vault_path.exists():
            return False

        try:
            # Load metadata
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)

            salt = base64.b64decode(metadata['salt'])
            key = self._derive_key(password, salt)

            # Verify password
            with open(self.lock_file, 'rb') as f:
                stored_hash = f.read()
                if hashlib.sha3_256(key).digest() != stored_hash:
                    return False

            fernet = Fernet(key)

            # Create temporary directory for decryption
            with tempfile.TemporaryDirectory() as tmp_dir:
                temp_path = Path(tmp_dir)

                with open(self.vault_path, 'rb') as vault:
                    # Skip salt
                    vault.read(SALT_SIZE)

                    # Read and decrypt structure
                    structure_data = b''
                    while True:
                        line = vault.readline()
                        if line == b'STRUCTURE_END\n':
                            break
                        structure_data += line

                    directory_structure = json.loads(fernet.decrypt(structure_data))

                    # Create directory structure
                    for path in directory_structure:
                        full_path = temp_path / path
                        full_path.parent.mkdir(parents=True, exist_ok=True)

                    # Decrypt files
                    for path in directory_structure:
                        item_path = temp_path / path
                        if not item_path.parent.exists():
                            item_path.parent.mkdir(parents=True)

                        file_data = b''
                        while True:
                            line = vault.readline()
                            if line == b'FILE_END\n':
                                break
                            file_data += line

                        if file_data:
                            decrypted = fernet.decrypt(file_data)
                            with open(item_path, 'wb') as f:
                                f.write(decrypted)

                # Move decrypted contents to original location
                if self.folder_path.exists():
                    shutil.rmtree(self.folder_path)
                shutil.copytree(temp_path, self.folder_path)

            if not keep_encrypted:
                os.remove(self.vault_path)
                os.remove(self.lock_file)
                os.remove(self.metadata_file)

            return True

        except Exception as e:
            print(f"Unlock error: {str(e)}")
            return False

    def unlock_with_recovery(self, recovery_code, new_password):
        try:
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)

            recovery_salt = base64.b64decode(metadata['recovery_salt'])
            recovery_key = self._derive_key(recovery_code, recovery_salt)

            if hashlib.sha3_256(recovery_key).hexdigest() != metadata['recovery_hash']:
                return False

            # Generate new encryption key
            new_salt = os.urandom(SALT_SIZE)
            new_key = self._derive_key(new_password, new_salt)

            # Update metadata and lock file
            metadata['salt'] = base64.b64encode(new_salt).decode()

            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f)

            with open(self.lock_file, 'wb') as f:
                f.write(hashlib.sha3_256(new_key).digest())

            return True

        except Exception:
            return False

class VaultManager:
    def __init__(self):
        self.locked_folders_file = Path.home() / '.secure_folders.json'
        self.locked_folders = self.load_state()

    def load_state(self):
        try:
            if self.locked_folders_file.exists():
                with open(self.locked_folders_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def save_state(self):
        with open(self.locked_folders_file, 'w') as f:
            json.dump(self.locked_folders, f)

    def add_locked_folder(self, path, recovery_code):
        folder_info = {
            'path': str(Path(path).resolve()),
            'recovery_code': recovery_code
        }
        self.locked_folders.append(folder_info)
        self.save_state()

    def remove_locked_folder(self, path):
        path = str(Path(path).resolve())
        self.locked_folders = [f for f in self.locked_folders if f['path'] != path]
        self.save_state()

    def get_locked_folders(self):
        return self.locked_folders

    def get_vault(self, path):
        return SecureVault(path)

class RecoveryDialog(tk.Toplevel):
    def __init__(self, parent, vault_manager):
        super().__init__(parent)
        self.title("Password Recovery")
        self.vault_manager = vault_manager
        self.parent = parent

        self.geometry("400x300")
        self.resizable(False, False)
        self.create_widgets()

        # Make dialog modal
        self.transient(parent)
        self.grab_set()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(main_frame, text="Enter Recovery Code:").pack(pady=5)
        self.recovery_entry = ttk.Entry(main_frame, width=30)
        self.recovery_entry.pack(pady=5)

        ttk.Label(main_frame, text="New Password:").pack(pady=5)
        self.new_pwd_entry = ttk.Entry(main_frame, show="•", width=30)
        self.new_pwd_entry.pack(pady=5)

        ttk.Label(main_frame, text="Confirm New Password:").pack(pady=5)
        self.confirm_pwd_entry = ttk.Entry(main_frame, show="•", width=30)
        self.confirm_pwd_entry.pack(pady=5)

        ttk.Button(main_frame, 
                  text="Reset Password",
                  command=self.reset_password).pack(pady=20)

    def reset_password(self):
        recovery_code = self.recovery_entry.get()
        new_password = self.new_pwd_entry.get()
        confirm_password = self.confirm_pwd_entry.get()

        if not all([recovery_code, new_password, confirm_password]):
            messagebox.showerror("Error", "Please fill all fields")
            return

        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if len(new_password) < MIN_PASSWORD_LENGTH:
            messagebox.showerror("Error", f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
            return

        selected_path = self.parent.path_entry.get()
        if not selected_path:
            messagebox.showerror("Error", "Please select a locked folder first")
            return

        try:
            vault = self.vault_manager.get_vault(selected_path)
            if vault.unlock_with_recovery(recovery_code, new_password):
                messagebox.showinfo("Success", "Password reset successful")
                self.destroy()
            else:
                messagebox.showerror("Error", "Invalid recovery code")
        except Exception as e:
            messagebox.showerror("Error", f"Password reset failed: {str(e)}")

class LockedFolderList(ttk.Frame):
    def __init__(self, parent, vault_manager):
        super().__init__(parent)
        self.vault_manager = vault_manager
        self.create_widgets()

    def create_widgets(self):
        # Create treeview
        columns = ('Folder', 'Status', 'Path')
        self.tree = ttk.Treeview(self, columns=columns, show='headings')

        # Configure columns
        self.tree.heading('Folder', text='Folder Name')
        self.tree.heading('Status', text='Status')
        self.tree.heading('Path', text='Full Path')

        self.tree.column('Folder', width=150)
        self.tree.column('Status', width=100)
        self.tree.column('Path', width=300)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Pack widgets
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind selection event
        self.tree.bind('<<TreeviewSelect>>', self.on_select)

        # Initial population
        self.refresh()

    def refresh(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Add current locked folders
        for folder in self.vault_manager.get_locked_folders():
            path = Path(folder['path'])
            self.tree.insert('', tk.END, values=(
                path.name,
                'Locked',
                str(path)
            ))

    def on_select(self, event):
        selected = self.tree.selection()
        if selected:
            values = self.tree.item(selected[0])['values']
            if values:
                # Update main window path entry
                app = self.master.master
                if hasattr(app, 'path_entry'):
                    app.path_entry.delete(0, tk.END)
                    app.path_entry.insert(0, values[2])

class FolderLockerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ultimate Folder Locker Pro")
        self.geometry("720x500")
        self.vault_manager = VaultManager()
        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.start_background_monitoring()

    def create_widgets(self):
        style = ttk.Style()
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TButton', padding=5)

        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Folder selection
        path_frame = ttk.Frame(main_frame)
        path_frame.pack(fill=tk.X, pady=10)

        ttk.Label(path_frame, text="Folder Path:").pack(side=tk.LEFT)
        self.path_entry = ttk.Entry(path_frame, width=50)
        self.path_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(path_frame, text="Browse", command=self.browse_folder).pack(side=tk.LEFT)

        # Password entry
        pwd_frame = ttk.Frame(main_frame)
        pwd_frame.pack(fill=tk.X, pady=10)
        ttk.Label(pwd_frame, text="Password:").pack(side=tk.LEFT)
        self.pwd_entry = ttk.Entry(pwd_frame, show="•", width=30)
        self.pwd_entry.pack(side=tk.LEFT, padx=5)

        # Options frame
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=10)

        self.keep_decrypted_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, 
                       text="Keep Decrypted Copy", 
                       variable=self.keep_decrypted_var).pack(side=tk.LEFT)

        # Action buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Lock Folder", 
                  command=self.lock_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Unlock Folder", 
                  command=self.unlock_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Recovery Options", 
                  command=self.show_recovery).pack(side=tk.LEFT, padx=5)

        # Locked folders list
        self.folder_list = LockedFolderList(main_frame, self.vault_manager)
        self.folder_list.pack(expand=True, fill=tk.BOTH, pady=10)

    def browse_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def lock_folder(self):
        path = self.path_entry.get()
        password = self.pwd_entry.get()
        keep_decrypted = self.keep_decrypted_var.get()

        if not path or not password:
            messagebox.showerror("Error", "Please provide both folder path and password")
            return

        try:
            vault = SecureVault(path)
            recovery_code = vault.lock(password, keep_decrypted)

            # Add to tracked folders
            self.vault_manager.add_locked_folder(path, recovery_code)
            self.folder_list.refresh()

            messagebox.showinfo("Success", 
                             f"Folder locked successfully!\nRecovery code: {recovery_code}\n"
                             "Please save this code securely.")
            self.clear_fields()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to lock folder: {str(e)}")

    def unlock_folder(self):
        path = self.path_entry.get()
        password = self.pwd_entry.get()
        keep_encrypted = self.keep_decrypted_var.get()

        if not path or not password:
            messagebox.showerror("Error", "Please provide both folder path and password")
            return

        try:
            vault = SecureVault(path)
            if vault.unlock(password, keep_encrypted):
                self.vault_manager.remove_locked_folder(path)
                self.folder_list.refresh()
                messagebox.showinfo("Success", "Folder unlocked successfully!")
                self.clear_fields()
            else:
                messagebox.showerror("Error", "Invalid password")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock folder: {str(e)}")

    def show_recovery(self):
        RecoveryDialog(self, self.vault_manager)

    def clear_fields(self):
        self.path_entry.delete(0, tk.END)
        self.pwd_entry.delete(0, tk.END)
        self.keep_decrypted_var.set(False)

    def start_background_monitoring(self):
        def run_monitor():
            image = Image.new('RGB', (64, 64), 'black')
            icon = pystray.Icon("folder_locker", image, "Folder Locker")
            icon.run()

        threading.Thread(target=run_monitor, daemon=True).start()

    def on_close(self):
        self.vault_manager.save_state()
        self.destroy()

if __name__ == "__main__":
    if platform.system() == 'Windows' and not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    app = FolderLockerApp()
    app.mainloop()
