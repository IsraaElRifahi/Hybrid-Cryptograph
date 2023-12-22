import sympy
import random
from Crypto.Cipher import DES3
from Crypto.Hash import SHA256
import tkinter as tk
from tkinter import Label, Button, messagebox, filedialog

def generate_elgamal_key(bits):
    p = sympy.randprime(2**(bits-1), 2**bits)
    
    # Find a generator g (primitive root modulo p)
    while True:
        g = random.randint(2, p-1)
        if all(pow(g, i, p) != 1 for i in range(1, p-1)):
            break
    return p, g

def generate_elgamal_public_key(p, g, private_key):
    return pow(g, private_key, p)


def square_and_multiply(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus

    return result

def elgamal_key_exchange(sender_private_key, receiver_public_key, prime):
    shared_key = square_and_multiply(receiver_public_key, sender_private_key, prime)
    return shared_key

def hash_key(key):
    hash_object = SHA256.new(data=key)
    return hash_object.digest()

def pad_data(data):
    padding_length = 8 - (len(data) % 8)
    padding = bytes([padding_length]) * padding_length
    return data + padding

class VideoDecryptionGUI:
    def __init__(self, master, shared_key):
        self.master = master
        master.title("Video Encryption and Decryption")

        self.shared_key = shared_key

        self.decrypt_button = Button(master, text="Decrypt Video", command=self.decrypt_video)
        self.decrypt_button.pack()

    def decrypt_video(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    encrypted_video_data = f.read()

                hashed_key = hash_key(str(self.shared_key).encode())
                key = hashed_key[:24]

                cipher = DES3.new(key, DES3.MODE_ECB)
                decrypted_video_data = cipher.decrypt(encrypted_video_data)

                padding_length = decrypted_video_data[-1]
                decrypted_video_data = decrypted_video_data[:-padding_length]

                output_file_path = filedialog.asksaveasfilename(defaultextension=".mp4")
                with open(output_file_path, "wb") as f:
                    f.write(decrypted_video_data)

                messagebox.showinfo("Decryption", "Video decrypted successfully!")
            except Exception as e:
                messagebox.showerror("Decryption Error", f"Error during decryption: {e}")
        else:
            messagebox.showwarning("Warning", "Please select a video file.")

class AliceGUI:
    def __init__(self, master):
        self.master = master
        master.title("Alice's Interface")

        self.label = Label(master, text="Alice's Interface")
        self.label.pack()

        self.generate_button = Button(master, text="Generate Keys and Key Exchange", command=self.generate_keys_and_exchange)
        self.generate_button.pack()

    def generate_keys_and_exchange(self):
        bits = 20
        prime, generator = generate_elgamal_key(bits)
        alice_private_key = random.randint(2, prime-1)
        alice_public_key = generate_elgamal_public_key(prime, generator, alice_private_key)

        messagebox.showinfo("Key Generation", f"Alice's Prime: {prime}\nAlice's Generator: {generator}\nAlice's Private Key: {alice_private_key}\nAlice's Public Key: {alice_public_key}")

        # Now, let Alice enter Bob's public key (replace this with your GUI for key entry)
        bob_public_key = int(input("Enter Bob's Public Key: "))

        # Perform key exchange with Bob
        shared_key = elgamal_key_exchange(alice_private_key, bob_public_key, prime)

        messagebox.showinfo("Key Exchange", f"\nShared Key: {shared_key}")

        # Now, set the shared_key attribute in the VideoDecryptionGUI instance
        video_root = tk.Tk()
        video_app = VideoDecryptionGUI(video_root, shared_key)
        video_root.mainloop()

if __name__ == "__main__":
    alice_root = tk.Tk()
    alice_app = AliceGUI(alice_root)
    alice_root.mainloop()
