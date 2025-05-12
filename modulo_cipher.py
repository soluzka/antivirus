def modulo_cipher_encode(text, key):
    """
    Encodes the given text using a Modulo Cipher with the provided key.
    """
    encoded = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encoded_char = chr((ord(char) - base + key) % 26 + base)
            encoded.append(encoded_char)
        else:
            encoded.append(char)  # Non-alphabetic characters remain unchanged
    return ''.join(encoded)

def modulo_cipher_decode(text, key):
    """
    Decodes the given text encoded with a Modulo Cipher using the provided key.
    """
    return modulo_cipher_encode(text, -key)

# Example usage
if __name__ == "__main__":
    plaintext = "Hello, World!"
    key = 3

    encoded_text = modulo_cipher_encode(plaintext, key)
    print(f"Encoded: {encoded_text}")

    decoded_text = modulo_cipher_decode(encoded_text, key)
    print(f"Decoded: {decoded_text}")
