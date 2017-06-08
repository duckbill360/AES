"""
105064506 鄭柏偉 HW2
AES
"""
import AES

if __name__ == "__main__":
    # ENCRYPTION
    # plaintext = '02015f283636ff00d3ffa4780808c5a3'
    # key = '6e27313178b6a308a676cfedf4c08a36'
    print('Encryption Mode : 1, Decryption Mode : 2')
    mode = int(input('Please choose Mode = '))

    if mode == 1:
        plaintext = input('You are in Encryption Mode\nPlease enter your plaintext : ')
        key = input('Please enter your key : ')
        # Encrypt
        # cipher should be '61cf0e005d73f11ab9a8dd34486224a6'
        print('Encrypted ciphertext : ', AES.AES_Encrypt(plaintext, key), '\n')
    elif mode == 2:
        # DECRYPTION
        ciphertext = input('You are in Decryption Mode\nPlease enter your ciphertext : ')
        key = input('Please enter your key : ')
        # Decrypt
        decrypted_plaintext = AES.AES_Decrypt(ciphertext, key)
        print('Decrypted plaintext : ', decrypted_plaintext)
    # END
