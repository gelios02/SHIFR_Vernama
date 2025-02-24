import math
import random
import sys
from collections import Counter

def generate_random_file(filename: str, size: int, use_lcg=False):

    if use_lcg:
        a = 1103515245
        c = 12345
        m = 2**31
        seed = 123456789

        x = seed
        with open(filename, 'wb') as f:
            for _ in range(size):
                x = (a * x + c) % m
                f.write((x & 0xFF).to_bytes(1, 'little'))
    else:
        with open(filename, 'wb') as f:
            for _ in range(size):
                byte = random.getrandbits(8)
                f.write(byte.to_bytes(1, 'little'))
    print(f"[OK] Сгенерирован файл '{filename}', {size} байт.")

def vernam_cipher(plaintext_file: str, key_file: str, output_file: str):

    try:
        with open(plaintext_file, 'rb') as f_plain, open(key_file, 'rb') as f_key, open(output_file, 'wb') as f_out:
            while True:
                chunk_plain = f_plain.read(1024)
                chunk_key = f_key.read(1024)
                if not chunk_plain or not chunk_key:
                    break
                xored = bytes(p ^ k for p, k in zip(chunk_plain, chunk_key))
                f_out.write(xored)
        print(f"[OK] Результат XOR записан в '{output_file}'")
    except FileNotFoundError as e:
        print("[Ошибка]", e)

def rc4_init(key: bytes) -> list:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_crypt(S: list, data: bytes) -> bytes:
    i = 0
    j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(byte ^ K)
    return bytes(out)

def rc4_file(key_str: str, input_file: str, output_file: str):
    try:
        with open(input_file, 'rb') as f_in:
            data = f_in.read()
    except FileNotFoundError:
        print(f"[Ошибка] Файл '{input_file}' не найден.")
        return

    key_bytes = key_str.encode('utf-8')
    S = rc4_init(key_bytes)
    result = rc4_crypt(S, data)

    with open(output_file, 'wb') as f_out:
        f_out.write(result)

    print(f"[OK] Файл '{input_file}' обработан RC4 и записан в '{output_file}'.")


def main():
    while True:
        print("\n===== МЕНЮ =====")
        print("1. Сгенерировать файл случайных символов")
        print("2. Шифр Вернама (XOR двух файлов)")
        print("3. RC4: Шифрование/расшифрование файла")
        print("4. Выход")

        choice = input("Выберите опцию (1-6): ").strip()
        if choice == '1':
            filename = input("Введите имя файла: ").strip()
            try:
                size = int(input("Введите размер (в байтах): ").strip())
            except ValueError:
                print("Некорректный размер!")
                continue
            use_lcg_input = input("Использовать LCG? (y/n): ").lower().strip()
            use_lcg = (use_lcg_input == 'y')
            generate_random_file(filename, size, use_lcg=use_lcg)
        elif choice == '2':
            plaintext_file = input("Введите путь к открытому (или шифр-) файлу: ").strip()
            key_file = input("Введите путь к файлу-ключу: ").strip()
            output_file = input("Введите имя выходного файла: ").strip()
            vernam_cipher(plaintext_file, key_file, output_file)
        elif choice == '3':
            key_str = input("Введите ключ (строка): ").strip()
            input_file = input("Введите путь к входному файлу: ").strip()
            output_file = input("Введите имя выходного файла: ").strip()
            rc4_file(key_str, input_file, output_file)
        elif choice == '4':
            print("Выход...")
            sys.exit(0)
        else:
            print("Неверный выбор. Повторите попытку.")

if __name__ == '__main__':
    main()
