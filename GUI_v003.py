import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import random
import pyperclip
import hashlib
import os

class Encoder:
    def __init__(self, key=None):
        if key is None:
            key = self.generate_key()
        self.key = key

    def generate_key(self, seed=None):
        characters = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~')
        if seed:
            random.seed(seed)
        random.shuffle(characters)
        return ''.join(characters)

    def encode_char(self, char):
        try:
            key_index = self.key.index(char)
            return self.key[(key_index + 1) % len(self.key)]
        except ValueError:
            # Leave characters not found in the key unchanged
            return char

    def encode_message(self, message):
        encoded_message = ''
        for char in message:
            encoded_message += self.encode_char(char)
        return encoded_message

class Decoder:
    def __init__(self, key):
        self.key = key

    def decode_char(self, encoded_char):
        try:
            key_index = self.key.index(encoded_char)
            return self.key[(key_index - 1) % len(self.key)]
        except ValueError:
            # Leave characters not found in the key unchanged
            return encoded_char

    def decode_message(self, encoded_message):
        decoded_message = ''
        for char in encoded_message:
            decoded_message += self.decode_char(char)
        return decoded_message

class EncoderDecoderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Encoder/Decoder")

        self.encoder = None
        self.decoder = None
        self.key_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.saved_key_path = None
        self.history = []

        self.create_widgets()

    def create_widgets(self):
        # Create Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Encoding/Decoding Tab
        encode_decode_frame = ttk.Frame(self.notebook)
        self.notebook.add(encode_decode_frame, text="Encode/Decode")
        self.create_encode_decode_widgets(encode_decode_frame)

        # Settings Tab
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        self.create_settings_widgets(settings_frame)

        # History Tab
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="History")
        self.create_history_widgets(history_frame)

    def create_encode_decode_widgets(self, frame):
        # Print Key Label
        self.print_key_label = ttk.Label(frame, text="Key:")
        self.print_key_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

        # Print Key Entry
        self.print_key_entry = ttk.Entry(frame, textvariable=self.key_var, width=50, state="readonly")
        self.print_key_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)

        # Copy Key Button
        self.copy_key_button = ttk.Button(frame, text="Copy Key", command=self.copy_key)
        self.copy_key_button.grid(row=0, column=2, padx=10, pady=10, sticky=tk.W)

        # Input Entry
        self.input_label = ttk.Label(frame, text="Enter Message:")
        self.input_label.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)

        self.input_entry = ttk.Entry(frame, width=50)
        self.input_entry.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W)

        # Encode Button
        self.encode_button = ttk.Button(frame, text="Encode", command=self.encode_message)
        self.encode_button.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)

        # Decode Button
        self.decode_button = ttk.Button(frame, text="Decode", command=self.decode_message)
        self.decode_button.grid(row=2, column=1, padx=10, pady=10, sticky=tk.W)

        # Output Label
        self.output_label = ttk.Label(frame, text="Result:")
        self.output_label.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)

        # Output Entry
        self.output_entry = ttk.Entry(frame, width=50, state="readonly")
        self.output_entry.grid(row=3, column=1, padx=10, pady=10, sticky=tk.W)

    def create_settings_widgets(self, frame):
        # Key Entry
        self.key_label = ttk.Label(frame, text="Enter Key (optional):")
        self.key_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

        self.key_entry = ttk.Entry(frame, textvariable=self.key_var, width=50)
        self.key_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)

        # Generate Key Button
        self.generate_key_button = ttk.Button(frame, text="Generate Key", command=self.generate_key)
        self.generate_key_button.grid(row=0, column=2, padx=10, pady=10, sticky=tk.W)

        # Password Protect Key Checkbutton
        self.password_protect_var = tk.BooleanVar()
        self.password_protect_checkbutton = ttk.Checkbutton(
            frame, text="Password Protect Key", variable=self.password_protect_var, command=self.toggle_password_entry
        )
        self.password_protect_checkbutton.grid(row=0, column=3, padx=10, pady=10, sticky=tk.W)

        # Set Password Label
        self.password_label = ttk.Label(frame, text="Set Password:")
        self.password_label.grid(row=0, column=4, padx=10, pady=10, sticky=tk.W)

        # Set Password Entry
        self.password_entry = ttk.Entry(frame, show="*", width=20, textvariable=self.password_var)
        self.password_entry.grid(row=0, column=5, padx=10, pady=10, sticky=tk.W)
        self.password_entry.config(state=tk.DISABLED)

        # Save Key Button
        self.save_key_button = ttk.Button(frame, text="Save Key", command=self.save_key)
        self.save_key_button.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)

        # Load Key Button
        self.load_key_button = ttk.Button(frame, text="Load Key", command=self.load_key)
        self.load_key_button.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W)

    def create_history_widgets(self, frame):
        # History Page Button
        self.history_text = tk.Text(frame, wrap="word", width=50, height=20)
        self.history_text.pack(padx=10, pady=10)

        # Insert history entries into the Text widget
        for entry in self.history:
            self.history_text.insert(tk.END, entry + "\n")

        self.history_text.configure(state="disabled")

    def toggle_password_entry(self):
        if self.password_protect_var.get():
            self.password_entry.config(state=tk.NORMAL)
        else:
            self.password_entry.config(state=tk.DISABLED)

    def generate_key(self):
        new_key = self.encoder.generate_key()
        self.key_var.set(new_key)

    def save_key(self):
        key_to_save = self.key_var.get()
        if key_to_save:
            file_path = tk.filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
            if file_path:
                password = self.password_entry.get() if self.password_protect_var.get() else None
                if password:
                    hashed_password = hashlib.sha256(password.encode()).hexdigest()
                    password_protected_key = self.encoder.generate_key(seed=hashed_password)
                    with open(file_path, "w") as file:
                        file.write(password_protected_key)
                else:
                    with open(file_path, "w") as file:
                        file.write(key_to_save)
                messagebox.showinfo("Key Saved", "Key saved successfully.")

    def load_key(self):
        file_path = tk.filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
        if file_path:
            try:
                with open(file_path, "r") as file:
                    loaded_key = file.read()
                    self.key_var.set(loaded_key)
            except Exception as e:
                messagebox.showerror("Error", f"Error loading key:\n{str(e)}")

    def copy_key(self):
        key_to_copy = self.key_var.get()
        pyperclip.copy(key_to_copy)

    def encode_message(self):
        key = self.key_var.get() if self.key_var.get() else None
        password = self.password_entry.get() if self.password_protect_var.get() else None

        if password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            password_protected_key = self.encoder.generate_key(seed=hashed_password)
            self.encoder = Encoder(password_protected_key)
            self.decoder = Decoder(password_protected_key)
        else:
            self.encoder = Encoder(key)
            self.decoder = Decoder(key)

        input_text = self.input_entry.get()
        encoded_text = self.encoder.encode_message(input_text)
        self.output_entry.configure(state="normal")
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, encoded_text)
        self.output_entry.configure(state="readonly")

        # Add to history
        self.history.append(f"Encoded: {input_text} -> {encoded_text}")

    def decode_message(self):
        key = self.key_var.get() if self.key_var.get() else None
        password = self.password_entry.get() if self.password_protect_var.get() else None

        if password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            password_protected_key = self.encoder.generate_key(seed=hashed_password)
            self.encoder = Encoder(password_protected_key)
            self.decoder = Decoder(password_protected_key)
        else:
            self.encoder = Encoder(key)
            self.decoder = Decoder(key)

        input_text = self.input_entry.get()
        decoded_text = self.decoder.decode_message(input_text)
        self.output_entry.configure(state="normal")
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, decoded_text)
        self.output_entry.configure(state="readonly")

        # Add to history
        self.history.append(f"Decoded: {input_text} -> {decoded_text}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncoderDecoderGUI(root)
    root.mainloop()
