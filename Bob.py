import sympy
import random
from Crypto.Cipher import DES3
from Crypto.Hash import SHA256
import tkinter as tk
from tkinter import Label, Button, messagebox, filedialog, Entry
from Crypto.Util.Padding import pad
import time


def generate_elgamal_public_key(p, g, private_key):
    return square_and_multiply(g, private_key, p)

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
    r = random.randint(2, prime-1)
    shared_key = square_and_multiply(receiver_public_key, sender_private_key, prime)
    return r, square_and_multiply(receiver_public_key, r, prime), shared_key

def hash_key(key):
    hash_object = SHA256.new(data=key)
    return hash_object.digest()

class VideoEncryptionGUI:
    def __init__(self, master, shared_key):
        self.master = master
        master.title("Video Encryption")

        self.shared_key = shared_key  #stores the shared_key (common key) for encryption

        self.encrypt_button = Button(master, text="Encrypt Video", command=self.encrypt_video)
        self.encrypt_button.pack()

    def encrypt_video(self):
        file_path = filedialog.askopenfilename() #open file to select a video
        if file_path:   #check if file path is selected 
            try:
                with open(file_path, "rb") as f:   #opens the selected file in binary
                    video_data = f.read()          #reads the contents of the selected file 

                hashed_key = hash_key(str(self.shared_key).encode()) #Generates a hashed key based on the shared_key provided
                key = hashed_key[:24]  # Truncates the hashed key to 24 bytes (for DES3 encryption)

                padded_video_data = pad(video_data, DES3.block_size)
                cipher = DES3.new(key, DES3.MODE_ECB)   #Initializes a DES3 cipher object for decryption using the derived key

                start_time = time.time()   #Records the start time for measuring encryption time
                encrypted_video_data = cipher.encrypt(padded_video_data)  #Removes padding from the decrypted data
                end_time = time.time()   #Records the end time after encryption

                output_file_path = filedialog.asksaveasfilename(defaultextension=".enc")    # to save the decrypted video with a default extension of ".mp4"
                with open(output_file_path, "wb") as f:
                    f.write(encrypted_video_data)    #Writes the encrypted video data to the output file


                elapsed_time = end_time - start_time   #Calculates the elapsed time for decryption 

                messagebox.showinfo("Encryption", f"Video encrypted successfully!\nTime taken: {elapsed_time:.2f} seconds")
            except Exception as e:
                messagebox.showerror("Encryption Error", f"Error during encryption: {e}")
        else:
            messagebox.showwarning("Warning", "Please select a video file.")

class BobGUI:
    def __init__(self, master):
        self.master = master
        master.title("Bob's Interface")

        self.label = Label(master, text="Bob's Interface")
        self.label.pack()

        master.geometry("300x200")  # Set the size of the window
        master.configure(bg="lightblue")  # Set background color

        self.prime_label = Label(master, text="Prime Number:")
        self.prime_label.pack()
        self.prime_entry = Entry(master, width=30)
        self.prime_entry.pack()

        self.generator_label = Label(master, text="Primitive Element:")
        self.generator_label.pack()
        self.generator_entry = Entry(master, width=30)
        self.generator_entry.pack()

        self.alice_public_key_label = Label(master, text="Alice's Public Key:")
        self.alice_public_key_label.pack()
        self.alice_public_key_entry = Entry(master, width=30)
        self.alice_public_key_entry.pack()

        self.generate_button = Button(master, text="Generate Keys and Key Exchange", command=self.generate_keys_and_exchange)
        self.generate_button.pack()

    def generate_keys_and_exchange(self):
        try:
            prime = int(self.prime_entry.get())
            generator = int(self.generator_entry.get())
            alice_public_key = int(self.alice_public_key_entry.get())

            bob_r, _, triple_des_key = self.perform_key_exchange(generator, prime, alice_public_key)

            messagebox.showinfo("Common Key", f"Shared Key of Bob: {triple_des_key}")

            self.master.destroy()  # Close Bob GUI

            video_root = tk.Tk()
            video_app = VideoEncryptionGUI(video_root, triple_des_key)  # Passing private key to VideoEncryptionGUI
            video_root.mainloop()
        except ValueError:
            messagebox.showerror("Error", "Please enter valid integer values for prime, generator, and Alice's public key.")

    def perform_key_exchange(self, generator, prime, alice_public_key):
        bob_private_key = random.randint(2, prime - 1)
        bob_public_key = generate_elgamal_public_key(prime, generator, bob_private_key)

        bob_r, _, triple_des_key = elgamal_key_exchange(bob_private_key, alice_public_key, prime)

        messagebox.showinfo("Bob's Key Generation", f"Bob's Private Key: {bob_private_key}\nBob's Public Key: {bob_public_key}")
        
        return bob_r, bob_public_key, triple_des_key

# Create Bob's GUI window
bob_root = tk.Tk()
bob_app = BobGUI(bob_root)
bob_root.mainloop()