import sympy #Provides functionalitites to work with prime numbers, modular arithmetic and various other mathematical concepts crucial to cryptography
import random # Generating random numbers
from Crypto.Cipher import DES3 #Cipher is for encryption and decryption algorithms
from Crypto.Hash import SHA256 #Hashing algorithms that transform data into a fixed-size hash output
import tkinter as tk #Creating graphical interfaces for applications
from tkinter import Label, Button, messagebox, filedialog
from Crypto.Util.Padding import unpad # Adding and removing padding from data
import time #tracking the time taken for encryption-decryption processes

def generate_elgamal_key(bits): #bits= bit length for the prime number (p)
    p = sympy.randprime(2**(bits-1), 2**bits) #generate random prime number(p) falling within this range (minimum,maximum)
    
    # Find a generator g (primitive root modulo p)
    while True:
        g = random.randint(2, p-1) 
        if all(pow(g, i, p) != 1 for i in range(1, p-1)): #check if g=primitive to p / (pow(g, i, p)=g^i mod p) 
                                                          #g is a primitive root modulo p, then g^i mod p should not equal 1 for any i in the range from 1 to p-1. 
                                                          #This condition indicates that g generates a complete set of residues modulo p.
                                                          #(Check if g is primitive if all g^i mod p is not qual to 1)
            break
    return p, g 

def generate_elgamal_public_key(p, g, private_key): #private key is generated in the GUI
    return pow(g, private_key, p) #(public_key= g^private_key mod p)

#for handling large numbers 
def square_and_multiply(base, exponent, modulus): #base^exponent mod modulus. Square and multiply if the value=1
    result = 1
    base = base % modulus

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus

    return result

#Generate a common key will be used as a key for 3DES after receiving Bob's public key (receiver)
def elgamal_key_exchange(sender_private_key, receiver_public_key, prime): 
    shared_key = square_and_multiply(receiver_public_key, sender_private_key, prime) #B^private_key mod p
    return shared_key

def hash_key(key): #key=input data that needs to be hashed/ 64 round ( to add security feature for the video)
    hash_object = SHA256.new(data=key)
    return hash_object.digest() #return byte string

class VideoDecryptionGUI:
    def __init__(self, master, shared_key): #for GUI
        self.master = master
        master.title("Video Decryption")

        self.shared_key = shared_key #Stores the shared_key (common key) for decryption

        self.decrypt_button = Button(master, text="Decrypt Video", command=self.decrypt_video)
        self.decrypt_button.pack()

    def decrypt_video(self): #handles decryption process when the button of decryption is clicked
        file_path = filedialog.askopenfilename() #open file to select a video
        if file_path: #check if file path is selected 
            try:
                with open(file_path, "rb") as f: #opens the selected file in binary
                    encrypted_video_data = f.read() #reads the contents of the selected file 

                hashed_key = hash_key(str(self.shared_key).encode()) #Generates a hashed key based on the shared_key provided
                key = hashed_key[:24] # Truncates the hashed key to 24 bytes (for DES3 encryption)

                cipher = DES3.new(key, DES3.MODE_ECB) #Initializes a DES3 cipher object for decryption using the derived key

                start_time = time.time()  #Records the start time for measuring decryption time
                decrypted_video_data = cipher.decrypt(encrypted_video_data) #Decrypts the encrypted video data using the DES3 cipher
                end_time = time.time() #Records the end time after decryption

                padding_length = decrypted_video_data[-1] #Retrieves the last byte to determine padding length
                decrypted_video_data = decrypted_video_data[:-padding_length] #Removes padding from the decrypted data

                output_file_path = filedialog.asksaveasfilename(defaultextension=".mp4") # to save the decrypted video with a default extension of ".mp4"
                with open(output_file_path, "wb") as f:
                    f.write(decrypted_video_data)  #Writes the decrypted video data to the output file

                elapsed_time = end_time - start_time #Calculates the elapsed time for decryption 

                messagebox.showinfo("Decryption", f"Video decrypted successfully!\nTime taken: {elapsed_time:.2f} seconds")
            except Exception as e:  #atches any exceptions that might occur during decryption
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

#Generation of prime (p), primitive(g), private key and public key
    def generate_keys_and_exchange(self):
        bits = 20
        prime, generator = generate_elgamal_key(bits)
        alice_private_key = random.randint(2, prime-1)
        alice_public_key = generate_elgamal_public_key(prime, generator, alice_private_key)

        messagebox.showinfo("Key Generation", f"Prime Number: {prime}\nPrimitive Element: {generator}\nAlice's Private Key: {alice_private_key}\nAlice's Public Key: {alice_public_key}")

        # Now, let Alice enter Bob's public key (replace this with your GUI for key entry) to generate the common key 
        bob_public_key = int(input("Enter Bob's Public Key: "))

        # Perform key exchange with Bob
        shared_key = elgamal_key_exchange(alice_private_key, bob_public_key, prime)

        messagebox.showinfo("Common Key", f"\nShared Key of Alice: {shared_key}")

        # Now, set the shared_key(common key) attribute in the VideoDecryptionGUI instance
        video_root = tk.Tk()
        video_app = VideoDecryptionGUI(video_root, shared_key)
        video_root.mainloop()

if __name__ == "__main__":
    alice_root = tk.Tk()
    alice_app = AliceGUI(alice_root)
    alice_root.mainloop()
