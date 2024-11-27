import os
from tables import Sbox, InvSbox, Rcon
from typing import List

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def pad_data(data, block_size=16):
    """Добавляет padding до кратности размера блока"""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def unpad_data(data):
    """Удаляет padding из данных"""
    padding_len = data[-1]
    return data[:-padding_len]


def data_to_blocks(data, block_size=16):
    """Разбивает данные на блоки"""
    data = pad_data(data, block_size)
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    return [text_to_matrix(block.hex()) for block in blocks]


def blocks_to_data(blocks):
    """Собирает блоки обратно в данные"""
    data = b''.join(matrix_to_bytes(block) for block in blocks)
    return unpad_data(data)


def text_to_matrix(hex_data):
    """Преобразует 16 байт в матрицу 4x4"""
    matrix = [[int(hex_data[i + j:i + j + 2], 16) for j in range(0, 8, 2)] for i in range(0, len(hex_data), 8)]
    return matrix


def matrix_to_bytes(matrix):
    """Преобразует матрицу обратно в байты"""
    return bytes([matrix[i][j] for i in range(4) for j in range(4)])


def binary_to_text(binary_data):
    """Преобразует бинарные данные в строку из 0 и 1"""
    return ''.join(f'{byte:08b}' for byte in binary_data)


def text_to_binary(binary_text):
    """Преобразует строку из 0 и 1 обратно в бинарные данные"""
    return bytes(int(binary_text[i:i + 8], 2) for i in range(0, len(binary_text), 8))


def key_to_block(hex_key):
    """
    Преобразует 16-байтовый ключ в матрицу 4x4.
    :param hex_key: Ключ в виде строки из 32 символов (16 байт в формате hex)
    :return: Матрица 4x4
    """
    res = []
    for i in range(0, len(hex_key), 8):
        row = [int(hex_key[j:j + 2], 16) for j in range(i, i + 8, 2)]
        res.append(row)
    return res


class AES:
    def __init__(self, key):
        self.change_key(key)

    def change_key(self, master_key):
        self.round_keys = master_key

        for i in range(4, 4 * 11):
            self.round_keys.append([])
            if i % 4 == 0:
                byte = self.round_keys[i - 4][0] \
                       ^ Sbox[self.round_keys[i - 1][1]] \
                       ^ Rcon[i // 4]
                self.round_keys[i].append(byte)

                for j in range(1, 4):
                    byte = self.round_keys[i - 4][j] \
                           ^ Sbox[self.round_keys[i - 1][(j + 1) % 4]]
                    self.round_keys[i].append(byte)
            else:
                for j in range(4):
                    byte = self.round_keys[i - 4][j] \
                           ^ self.round_keys[i - 1][j]
                    self.round_keys[i].append(byte)

    def add_round_key(self, state_matrix, key_matrix):
        for i in range(4):
            for j in range(4):
                state_matrix[i][j] ^= key_matrix[i][j]

    def sub_bytes(self, matrix: List[List[str]]):
        for i in range(4):
            for j in range(4):
                matrix[i][j] = Sbox[matrix[i][j]]

    def shift_rows(self, matrix):
        matrix[1] = matrix[1][1:] + matrix[1][:1]
        matrix[2] = matrix[2][2:] + matrix[2][:2]
        matrix[3] = matrix[3][3:] + matrix[3][:3]

    def inv_shift_rows(self, matrix):
        matrix[1] = matrix[1][-1:] + matrix[1][:-1]
        matrix[2] = matrix[2][-2:] + matrix[2][:-2]
        matrix[3] = matrix[3][-3:] + matrix[3][:-3]

    def inv_sub_bytes(self, matrix):
        for i in range(4):
            for j in range(4):
                matrix[i][j] = InvSbox[matrix[i][j]]

    def mix_single_column(self, a):
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ xtime(a[0] ^ a[1])
        a[1] ^= t ^ xtime(a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)

    def mix_columns(self, s):
        for i in range(4):
            self.mix_single_column(s[i])

    def inv_mix_columns(self, s):
        for i in range(4):
            u = xtime(xtime(s[i][0] ^ s[i][2]))
            v = xtime(xtime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v

        self.mix_columns(s)

    def encrypt(self, plaintext):
        self.add_round_key(plaintext, self.round_keys[:4])
        for i in range(1, 10):
            self.sub_bytes(plaintext)
            self.shift_rows(plaintext)
            self.mix_columns(plaintext)
            self.add_round_key(plaintext, self.round_keys[4 * i:4 * (i + 1)])
        self.sub_bytes(plaintext)
        self.shift_rows(plaintext)
        self.add_round_key(plaintext, self.round_keys[40:])
        return plaintext

    def decrypt(self, ciphertext):
        self.add_round_key(ciphertext, self.round_keys[40:])
        self.inv_shift_rows(ciphertext)
        self.inv_sub_bytes(ciphertext)
        for i in range(9, 0, -1):
            self.add_round_key(ciphertext, self.round_keys[4 * i:4 * (i + 1)])
            self.inv_mix_columns(ciphertext)
            self.inv_shift_rows(ciphertext)
            self.inv_sub_bytes(ciphertext)
        self.add_round_key(ciphertext, self.round_keys[:4])
        return ciphertext

    def encrypt_blocks(self, blocks):
        for i in range(len(blocks)):
            blocks[i] = self.encrypt(blocks[i])
        return blocks

    def decrypt_blocks(self, blocks):
        for i in range(len(blocks)):
            blocks[i] = self.decrypt(blocks[i])
        return blocks


def process_directory(aes, dir_path, action):
    """Шифрует или дешифрует все файлы в директории."""
    output_dir = f"{dir_path}_processed"
    os.makedirs(output_dir, exist_ok=True)

    for root, dirs, files in os.walk(dir_path):
        for file in files:
            input_file_path = os.path.join(root, file)
            rel_path = os.path.relpath(input_file_path, dir_path)
            output_file_path = os.path.join(output_dir, rel_path)
            os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

            with open(input_file_path, 'rb') as file:
                data = file.read()

            if action == 1:  # Шифрование
                blocks = data_to_blocks(data)
                encrypted_blocks = aes.encrypt_blocks(blocks)
                processed_data = blocks_to_data(encrypted_blocks)
            elif action == 2:  # Дешифрование
                blocks = data_to_blocks(data)
                decrypted_blocks = aes.decrypt_blocks(blocks)
                processed_data = blocks_to_data(decrypted_blocks)

            with open(output_file_path, 'wb') as file:
                file.write(processed_data)
            print(f'Processed file: {input_file_path} -> {output_file_path}')

    print(f"All files processed. Output directory: {output_dir}")


if __name__ == '__main__':
    key = input('Enter the key (16 bytes in hexadecimal): ')
    key_01 = key_to_block(key)
    aes = AES(key=key_01)

    action = int(input('Enter action (1 - encryption, 2 - decryption): '))
    path = input('Enter the file or directory path: ')

    if os.path.isfile(path):
        base, ext = os.path.splitext(path)

        with open(path, 'rb') as file:
            data = file.read()

        if action == 1:
            blocks = data_to_blocks(data)
            encrypted_blocks = aes.encrypt_blocks(blocks)
            encrypted_data = blocks_to_data(encrypted_blocks)
            new_path = f"{base}_encrypted{ext}"
            with open(new_path, 'wb') as file:
                file.write(encrypted_data)
            print(f'File encrypted successfully: {new_path}')
        elif action == 2:
            blocks = data_to_blocks(data)
            decrypted_blocks = aes.decrypt_blocks(blocks)
            decrypted_data = blocks_to_data(decrypted_blocks)
            new_path = f"{base.replace('_encrypted', '')}_decrypted{ext}"
            with open(new_path, 'wb') as file:
                file.write(decrypted_data)
            print(f'File decrypted successfully: {new_path}')
    elif os.path.isdir(path):
        process_directory(aes, path, action)
    else:
        print("Invalid path specified.")
