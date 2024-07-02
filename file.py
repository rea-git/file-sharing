import tkinter as tk
from tkinter import filedialog, messagebox
import os
import hashlib
import bcrypt
from cryptography.fernet import Fernet

# Securely generate a key for encryption (in practice, store this securely)
key = Fernet.generate_key()
cipher = Fernet(key)

# Securely hashed password for demonstration purposes
users = {"admin": bcrypt.hashpw("password".encode(), bcrypt.gensalt()).decode()}

class FileSharingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Sharing App")
        self.root.geometry("500x400")
        
        self.authenticated = False
        
        # Create frames
        self.login_frame = tk.Frame(self.root)
        self.main_frame = tk.Frame(self.root)
        
        self.create_login_frame()
        self.create_main_frame()
        
        self.login_frame.pack()
    
    def create_login_frame(self):
        tk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.pack(pady=5)
        
        tk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.pack(pady=5)
        
        tk.Button(self.login_frame, text="Login", command=self.login).pack(pady=20)
    
    def create_main_frame(self):
        tk.Button(self.main_frame, text="Upload File", command=self.upload_file).pack(pady=10)
        tk.Button(self.main_frame, text="Download File", command=self.download_file).pack(pady=10)
        tk.Button(self.main_frame, text="View Files", command=self.view_files).pack(pady=10)
        tk.Button(self.main_frame, text="Delete File", command=self.delete_file).pack(pady=10)
        self.status_label = tk.Label(self.main_frame, text="", fg="red")
        self.status_label.pack(pady=20)
        
        # Listbox to display files
        self.file_listbox = tk.Listbox(self.main_frame)
        self.file_listbox.pack(pady=10)
    
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get().encode()
        
        if username in users and bcrypt.checkpw(password, users[username].encode()):
            self.authenticated = True
            self.login_frame.pack_forget()
            self.main_frame.pack()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")
    
    def upload_file(self):
        if not self.authenticated:
            return
        
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    data = file.read()
                    encrypted_data = cipher.encrypt(data)
                
                file_name = os.path.basename(file_path)
                with open(f"server/{file_name}.enc", "wb") as file:
                    file.write(encrypted_data)
                
                self.status_label.config(text="File uploaded successfully!", fg="green")
                self.update_file_list()
            except Exception as e:
                self.status_label.config(text=f"Error: {str(e)}", fg="red")
    
    def download_file(self):
        if not self.authenticated:
            return
        
        selected_files = self.file_listbox.curselection()
        if selected_files:
            file_name = self.file_listbox.get(selected_files[0])
            file_path = f"server/{file_name}"
            try:
                with open(file_path, "rb") as file:
                    encrypted_data = file.read()
                    data = cipher.decrypt(encrypted_data)
                
                save_path = filedialog.asksaveasfilename(defaultextension=".txt")
                if save_path:
                    with open(save_path, "wb") as file:
                        file.write(data)
                
                self.status_label.config(text="File downloaded successfully!", fg="green")
            except Exception as e:
                self.status_label.config(text=f"Error: {str(e)}", fg="red")
    
    def view_files(self):
        if not self.authenticated:
            return
        
        self.update_file_list()
        self.status_label.config(text="Files listed below.", fg="blue")
    
    def delete_file(self):
        if not self.authenticated:
            return
        
        selected_files = self.file_listbox.curselection()
        if selected_files:
            file_name = self.file_listbox.get(selected_files[0])
            file_path = f"server/{file_name}"
            try:
                os.remove(file_path)
                self.status_label.config(text="File deleted successfully!", fg="green")
                self.update_file_list()
            except Exception as e:
                self.status_label.config(text=f"Error: {str(e)}", fg="red")
    
    def update_file_list(self):
        self.file_listbox.delete(0, tk.END)
        files = os.listdir("server/")
        for file in files:
            self.file_listbox.insert(tk.END, file)

if __name__ == "__main__":
    if not os.path.exists("server"):
        os.makedirs("server")
    
    root = tk.Tk()
    app = FileSharingApp(root)
    root.mainloop()
