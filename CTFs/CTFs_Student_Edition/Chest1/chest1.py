import string

# Function to decrypt Caesar cipher with a given shift, converting all to lowercase
def caesar_decrypt(text, shift):
    decrypted_text = []
    for char in text:
        if char.isalpha():  # Only apply decryption to alphabetic characters
            # Convert to lowercase, shift, and decrypt
            decrypted_text.append(chr(((ord(char.lower()) - 97 - shift) % 26) + 97))
        else:
            decrypted_text.append(char)  # Keep non-alphabetic characters as is
    return ''.join(decrypted_text)


def try_decrypt_caesar_cipher():
    # Read the content of the encrypted text from the file
    file_path = './enc.txt'

    with open(file_path, 'r') as file:
        cipher_text = file.read()

    # Try all 26 shifts and save the results to separate files
    for shift in range(1, 27):
        decrypted_text = caesar_decrypt(cipher_text, shift)
        output_filename = f"decrypted_shift_{shift}.txt"
        with open(output_filename, 'w') as output_file:
            output_file.write(decrypted_text)

        print(f"Decryption for shift {shift} saved to {output_filename}")


def try_atBash_cipher():
    # Read the content of the encrypted text from the file
    file_path = './enc.txt'

    with open(file_path, 'r') as file:
        cipher_text = file.read()

    # Atbash cipher decryption
    atbash_decrypted_text = []
    for char in cipher_text:
        if char.isalpha():  # Only apply decryption to alphabetic characters
            # Convert to lowercase and decrypt using Atbash
            atbash_decrypted_text.append(chr(219 - ord(char.lower())))
        else:
            atbash_decrypted_text.append(char)  # Keep non-alphabetic characters as is

    output_filename = "atbash_decrypted.txt"
    with open(output_filename, 'w') as output_file:
        output_file.write(''.join(atbash_decrypted_text))

    print(f"Atbash decryption saved to {output_filename}")

try_atBash_cipher()
