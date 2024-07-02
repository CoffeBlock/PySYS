import random
import pyperclip
import hashlib

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

def generate_key():
  encoder = Encoder()
  key = encoder.generate_key()
  print("Generated Key:", key)
  pyperclip.copy(key)
  print("Key copied to clipboard.")

def save_key():
  encoder = Encoder()
  key = input("Enter the key to save: ")
  file_path = input("Enter the file path to save the key (e.g., /path/to/key.key): ")
  with open(file_path, "w") as file:
    file.write(key)
  print("Key saved successfully.")

def load_key():
  file_path = input("Enter the file path to load the key from (e.g., /path/to/key.key): ")
  try:
    with open(file_path, "r") as file:
      loaded_key = file.read()
      print("Loaded Key:", loaded_key)
  except Exception as e:
    print("Error loading key:", str(e))

def encode_message():
  key = input("Enter the key: ")
  message = input("Enter the message to encode: ")
  encoder = Encoder(key)
  encoded_message = encoder.encode_message(message)
  print("Encoded Message:", encoded_message)

def decode_message():
  key = input("Enter the key: ")
  message = input("Enter the message to decode: ")
  decoder = Decoder(key)
  decoded_message = decoder.decode_message(message)
  print("Decoded Message:", decoded_message)

def main():
  while True:
    print("1. Generate Key")
    print("2. Save Key")
    print("3. Load Key")
    print("4. Encode Message")
    print("5. Decode Message")
    print("6. Exit")
    choice = input("Enter your choice (1-6): ")

    if choice == "1":
      generate_key()
    elif choice == "2":
      save_key()
    elif choice == "3":
      load_key()
    elif choice == "4":
      encode_message()
    elif choice == "5":
      decode_message()
    elif choice == "6":
      break
    else:
      print("Invalid choice. Please try again.")

if __name__ == "__main__":
  main()
