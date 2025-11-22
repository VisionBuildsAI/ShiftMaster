# Simple Caesar Cipher
# Encrypts and decrypts letters using a fixed shift (3 by default)
# Uppercase letters are preserved, symbols remain unchanged
# Author: Your Name
# GitHub-ready version

def caesar(text, shift=3, encrypt=True):
    """
    Core Caesar cipher function.
    
    Args:
        text (str): The message to encrypt or decrypt.
        shift (int, optional): Number of positions to shift (default is 3).
        encrypt (bool, optional): True to encrypt, False to decrypt.

    Returns:
        str: The encrypted or decrypted message.
    """
    # Validate shift value
    if not isinstance(shift, int):
        return 'Shift must be an integer value.'
    if shift < 1 or shift > 25:
        return 'Shift must be an integer between 1 and 25.'

    alphabet = 'abcdefghijklmnopqrstuvwxyz'

    # Reverse shift for decryption
    if not encrypt:
        shift = -shift

    # Create shifted alphabet for translation
    shifted_alphabet = alphabet[shift:] + alphabet[:shift]
    translation_table = str.maketrans(
        alphabet + alphabet.upper(), 
        shifted_alphabet + shifted_alphabet.upper()
    )

    # Translate the text
    encrypted_text = text.translate(translation_table)
    return encrypted_text


def encrypt(text):
    """
    Encrypt a message using the Caesar cipher with fixed shift.
    """
    return caesar(text)


def decrypt(text):
    """
    Decrypt a message using the Caesar cipher with fixed shift.
    """
    return caesar(text, encrypt=False)


# ---------------------------
# Interactive usage
# ---------------------------

# Ask the user whether to encrypt or decrypt
choice = input("Choose option (encrypt/decrypt): ").lower()

if choice not in ['encrypt', 'decrypt']:
    print("ERROR: Invalid option")
else:
    # Get the actual message from the user
    message = input("Enter your message: ")

    # Perform encryption or decryption
    if choice == 'encrypt':
        result = encrypt(message)
        print("Encrypted:", result)
    else:
        result = decrypt(message)
        print("Decrypted:", result)
