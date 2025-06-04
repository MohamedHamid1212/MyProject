import os
import shutil
import webbrowser
import hashlib
import json
import subprocess
from tkinter import filedialog
from datetime import datetime

# === Quarantine Tracking ===
def save_quarantine_info(quarantine_path, files):
    with open("quarantine_info.txt", "w") as file:
        file.write(f"{quarantine_path}\n")
        for f in files:
            file.write(f"{f}\n")

def load_quarantine_info():
    if os.path.exists("quarantine_info.txt"):
        with open("quarantine_info.txt", "r") as file:
            lines = file.readlines()
            if lines:
                quarantine_path = lines[0].strip()
                files = [line.strip() for line in lines[1:]]
                return quarantine_path, files
    return "", []

def open_folder(path):
    if os.path.exists(path):
        webbrowser.open(path)

def log_quarantine(folder, files):
    log_path = os.path.join(folder, "quarantine_log.txt")
    with open(log_path, "w") as log:
        for f in files:
            log.write(f"{f}\n")

def quarantine_files(base_folder, file_list, quarantine_path):
    os.makedirs(quarantine_path, exist_ok=True)
    for file in file_list:
        src = os.path.join(base_folder, file)
        dst = os.path.join(quarantine_path, file)
        try:
            if os.path.isfile(src):
                shutil.move(src, dst)
        except Exception as e:
            print(f"Error moving {file}: {e}")
    save_quarantine_info(quarantine_path, file_list)
    return quarantine_path

def move_quarantined_files(current_quarantine_path, new_quarantine_path, quarantined_files):
    os.makedirs(new_quarantine_path, exist_ok=True)
    for item in os.listdir(current_quarantine_path):
        src = os.path.join(current_quarantine_path, item)
        dst = os.path.join(new_quarantine_path, item)
        try:
            if os.path.isfile(src):
                shutil.move(src, dst)
            elif os.path.isdir(src):
                shutil.move(src, dst)
        except Exception as e:
            print(f"Error moving {item} to new path: {e}")

# === Hash Saving ===
def save_hash(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return

    hash_file = "known_hashes.json"
    if os.path.exists(hash_file):
        with open(hash_file, "r") as f:
            known_hashes = json.load(f)
    else:
        known_hashes = {"md5": [], "sha256": []}

    if md5 not in known_hashes["md5"]:
        known_hashes["md5"].append(md5)
    if sha256 not in known_hashes["sha256"]:
        known_hashes["sha256"].append(sha256)

    with open(hash_file, "w") as f:
        json.dump(known_hashes, f, indent=2)

# === Virus Path Tracking ===
VIRUS_PATHS_FILE = "virus_paths.json"
VIRUS_FOLDER = "simulated_virus"

def load_virus_paths():
    if os.path.exists(VIRUS_PATHS_FILE):
        with open(VIRUS_PATHS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_virus_paths(paths):
    with open(VIRUS_PATHS_FILE, "w") as f:
        json.dump(paths, f, indent=2)

def find_file(filename, root="C:/"):
    for dirpath, _, files in os.walk(root):
        if filename in files:
            return os.path.join(dirpath, filename)
    return None

def update_moved_virus_paths():
    paths = load_virus_paths()
    updated = {}
    for name, old_path in paths.items():
        if os.path.exists(old_path):
            updated[name] = old_path
        else:
            found = find_file(name)
            if found:
                updated[name] = found
            else:
                updated[name] = old_path
    save_virus_paths(updated)
    return updated

def get_all_virus_paths_with_time():
    paths = update_moved_virus_paths()
    detailed = {}
    for name, path in paths.items():
        if os.path.exists(path):
            try:
                ctime = os.path.getctime(path)
                created_str = datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
                detailed[name] = {"path": path, "created": created_str}
            except:
                detailed[name] = {"path": path, "created": "Unknown"}
    return detailed

# === Virus Generator ===
def generate_virus_by_type(vtype, folder="simulated_virus"):
    os.makedirs(folder, exist_ok=True)

    payload_map = {
        "beeper": ("beep_simulation", """import time
for _ in range(5):
    print("Beep!")
    time.sleep(1)
"""),
        "message_spam": ("message_spam", """import tkinter as tk
from tkinter import messagebox
root = tk.Tk()
root.withdraw()
for _ in range(10):
    messagebox.showinfo("Alert", "YOU HAVE BEEN HACKED")
"""),
        "wallpaper_changer": ("wallpaper_changer", r"""import ctypes
image_path = r"C:\Users\User\Desktop\hacked.jpg"
ctypes.windll.user32.SystemParametersInfoW(20, 0, image_path, 3)
"""),
        "folder_bomb": ("folder_bomb", r"""import os
desktop = os.path.join(os.path.expanduser("~"), "Desktop")
base_path = desktop
for i in range(1, 25):
    base_path = os.path.join(base_path, f"folder{i}")
    os.makedirs(base_path, exist_ok=True)
""")
    }

    if vtype in payload_map:
        name, code = payload_map[vtype]
        py_path = os.path.join(folder, f"{name}.py")
        exe_path = os.path.join(folder, f"{name}.exe")

        with open(py_path, "w") as f:
            f.write(code)

        args = ["py", "-m", "PyInstaller", "--onefile"]
        if vtype != "beeper":
            args.append("--noconsole")
        args += ["--distpath", folder, "--workpath", "build", "--specpath", "build", py_path]

        try:
            subprocess.run(args, check=True)
            if os.path.exists(py_path):
                os.remove(py_path)
            spec_file = os.path.join("build", f"{name}.spec")
            if os.path.exists(spec_file):
                os.remove(spec_file)

            save_hash(exe_path)

            paths = load_virus_paths()
            paths[f"{name}.exe"] = exe_path
            save_virus_paths(paths)

        except subprocess.CalledProcessError as e:
            print(f"❌ PyInstaller failed with return code {e.returncode}")
        except FileNotFoundError as e:
            print(f"❌ PyInstaller not found: {e}")

    elif vtype == "eicar":
        eicar_string = (
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        script_path = os.path.join(folder, "eicar_test_file.com")
        with open(script_path, 'w') as f:
            f.write(eicar_string)
        save_hash(script_path)

        paths = load_virus_paths()
        paths["eicar_test_file.com"] = script_path
        save_virus_paths(paths)

    else:
        with open(os.path.join(folder, "unknown_fake.txt"), "w") as f:
            f.write("Unknown virus type generated.")
