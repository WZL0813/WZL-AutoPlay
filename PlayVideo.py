import time
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import threading
import json
import hashlib
import base64

class PlayVideoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PlayVideo")
        self.root.resizable(False, False)
        # 修改图标路径为绝对路径
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PlayVideoWZL.ico")
        self.root.iconbitmap(icon_path)
        
        self.video_path = tk.StringVar()
        self.countdown_time = tk.IntVar(value=300)
        
        self.load_config()
        self.create_widgets()
        self.start_countdown()
        self.print_password_hash()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def print_password_hash(self):
        password_hash = self.hash_password("WangZiLong-PlayVideo")
        print(f"Password Hash: {password_hash}")

    def start_countdown(self):
        def countdown():
            for i in range(self.countdown_time.get(), 0, -1):
                if not self.root.winfo_exists():
                    return
                self.root.title(f"PlayVideo-WZL (倒计时: {i}秒)")
                time.sleep(1)
            self.play_video_immediately()

        countdown_thread = threading.Thread(target=countdown)
        countdown_thread.daemon = True
        countdown_thread.start()

    def play_video_immediately(self):
        video_path = self.video_path.get()
        if not video_path:
            messagebox.showwarning("输入错误", "请选择一个视频文件。")
            return
        
        if not os.path.exists(video_path):
            messagebox.showerror("错误", "视频文件不存在或路径无效。")
            return
        
        try:
            webbrowser.open(video_path)
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("错误", f"无法打开视频文件: {e}")

    def create_widgets(self):
        # Video Path
        tk.Label(self.root, text="视频路径:").grid(row=0, column=0, padx=10, pady=10)
        tk.Entry(self.root, textvariable=self.video_path, width=50).grid(row=0, column=1, padx=10, pady=10)
        tk.Button(self.root, text="选择视频", command=self.select_video_path).grid(row=0, column=2, padx=10, pady=10)

        # Countdown Time
        tk.Label(self.root, text="倒计时时间(秒):").grid(row=1, column=0, padx=10, pady=10)
        countdown_entry = tk.Entry(self.root, textvariable=self.countdown_time, width=10)
        countdown_entry.grid(row=1, column=1, padx=10, pady=10)
        countdown_entry.bind("<FocusOut>", self.validate_countdown_time)

        # Buttons
        tk.Button(self.root, text="保存配置", command=self.save_config).grid(row=2, column=0, pady=10)
        tk.Button(self.root, text="加载配置", command=self.load_config).grid(row=2, column=1, pady=10)

        # WZL Link
        wzl_label = tk.Label(self.root, text="WZL", fg="blue", cursor="hand2")
        wzl_label.grid(row=3, column=2, sticky="se", padx=10, pady=10)
        wzl_label.bind("<Button-1>", lambda e: webbrowser.open("https://wzl0813.github.io"))

    def select_video_path(self):
        password = simpledialog.askstring("输入密码", "请输入密码以更改视频路径:", show='*')
        if password is None:
            return  # 用户取消输入，直接返回
        input_hash = self.hash_password(password)
        correct_hash = "f5ed02886fead35d04df1fa5229b5aea380f3d74151cd8440fbfc79b66711d73"
        if input_hash == correct_hash:
            file_path = filedialog.askopenfilename(filetypes=[("视频文件", "*.mp4 *.avi *.mkv")])
            if file_path:
                self.video_path.set(file_path.replace("\\", "/"))
        else:
            messagebox.showerror("错误", f"密码错误，无法更改视频路径。\n输入哈希值: {input_hash}\n正确哈希值: {correct_hash}")

    def generate_key(self):
        key = hashlib.sha256("WangZiLong-PlayVideo".encode()).digest()
        return base64.urlsafe_b64encode(key[:32])

    def encrypt_data(self, data):
        key = self.generate_key()
        # 使用base64编码和简单的异或加密
        data_str = json.dumps(data)
        encrypted = bytearray(data_str.encode())
        key_bytes = key[:len(encrypted)]
        for i in range(len(encrypted)):
            encrypted[i] ^= key_bytes[i % len(key_bytes)]
        return base64.urlsafe_b64encode(encrypted)

    def decrypt_data(self, encrypted_data):
        key = self.generate_key()
        # 使用base64解码和简单的异或解密
        encrypted = base64.urlsafe_b64decode(encrypted_data)
        key_bytes = key[:len(encrypted)]
        decrypted = bytearray(encrypted)
        for i in range(len(decrypted)):
            decrypted[i] ^= key_bytes[i % len(key_bytes)]
        return json.loads(decrypted.decode())

    def save_config(self):
        confirm = messagebox.askyesno("确认保存", "您确定要保存配置吗？")
        if confirm:
            password = simpledialog.askstring("输入密码", "请输入密码:", show='*')
            input_hash = self.hash_password(password)
            correct_hash = "f5ed02886fead35d04df1fa5229b5aea380f3d74151cd8440fbfc79b66711d73"
            if input_hash == correct_hash:
                config_data = {
                    "video_path": self.video_path.get(),
                    "countdown_time": self.countdown_time.get()
                }
                config_path = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "WZL", "PlayVideo")
                os.makedirs(config_path, exist_ok=True)
                encrypted_data = self.encrypt_data(config_data)
                with open(os.path.join(config_path, "config.json"), "wb") as config_file:
                    config_file.write(encrypted_data)
                messagebox.showinfo("保存成功", "配置已保存并加密。")
            else:
                messagebox.showerror("错误", f"密码错误，无法保存配置。\n输入哈希值: {input_hash}\n正确哈希值: {correct_hash}")

    def load_config(self):
        config_path = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "WZL", "PlayVideo", "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "rb") as config_file:
                    encrypted_data = config_file.read()
                    config_data = self.decrypt_data(encrypted_data)
                    self.video_path.set(config_data["video_path"])
                    self.countdown_time.set(config_data.get("countdown_time", 10))
            except Exception as e:
                os.remove(config_path)
                messagebox.showwarning("配置文件错误", f"配置文件解密失败，已删除。错误详情: {str(e)}")

    def validate_countdown_time(self, event):
        password = simpledialog.askstring("输入密码", "请输入密码以更改倒计时时间:", show='*')
        if password is None:
            return  # 用户取消输入，直接返回
        input_hash = self.hash_password(password)
        correct_hash = "f5ed02886fead35d04df1fa5229b5aea380f3d74151cd8440fbfc79b66711d73"
        if input_hash != correct_hash:
            messagebox.showerror("错误", f"密码错误，无法更改倒计时时间。\n输入哈希值: {input_hash}\n正确哈希值: {correct_hash}")
            self.countdown_time.set(300)

if __name__ == "__main__":
    root = tk.Tk()
    app = PlayVideoApp(root)
    root.mainloop()