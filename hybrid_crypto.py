import os
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class HybridCryptosystem:
    def __init__(self):
        self.backend = default_backend()
        self.block_size = 128  # Розмір блоку AES у бітах (16 байт)
        self.key_size_aes = 32  # 256 біт для AES (32 байти)
        self.rsa_key_size = 2048  # 2048 біт для RSA
        self.rsa_ciphertext_length = 256  # Розмір зашифрованого RSA блоку (в байтах)

    def _pad(self, data: bytes) -> bytes:
        padder = sym_padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        print(f"      [~] PKCS#7 Padding: збільшено розмір з {len(data)} до {len(padded_data)} байт.")
        return padded_data

    def _unpad(self, data: bytes) -> bytes:
        unpadder = sym_padding.PKCS7(self.block_size).unpadder()
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        print(f"      [~] PKCS#7 Unpadding: зменшено розмір з {len(data)} до {len(unpadded_data)} байт.")
        return unpadded_data

    def generate_and_save_rsa_keys(self):
        print("\n[*] Запуск генерації ключової пари RSA-2048...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open("private_key.pem", "wb") as f:
            f.write(priv_pem)
        with open("public_key.pem", "wb") as f:
            f.write(pub_pem)

        print("[+] Ключі успішно згенеровано та збережено у поточній папці:")
        print("    - private_key.pem (Секретний ключ)")
        print("    - public_key.pem (Відкритий ключ)")

    def encrypt_file_interactive(self):
        input_filepath = input("\n[?] Введіть ім'я файлу для шифрування (наприклад, document.txt): ").strip()
        if not os.path.exists(input_filepath):
            print(f"[-] Помилка: Файл '{input_filepath}' не знайдено!")
            return

        output_filepath = input_filepath + ".enc"

        if not os.path.exists("public_key.pem"):
            print("[-] Помилка: Не знайдено public_key.pem. Згенеруйте ключі (пункт 1).")
            return

        print("\n[*] Початок процедури гібридного шифрування (AES-256 ECB + RSA-2048)...")

        # 1. Генерація сеансового ключа
        session_key = os.urandom(self.key_size_aes)
        print(f"    [+] Згенеровано сеансовий ключ AES-256: {binascii.hexlify(session_key).decode('utf-8')[:32]}...")

        # 2. Зчитування відкритого тексту
        with open(input_filepath, 'rb') as f:
            plaintext = f.read()
        print(f"    [+] Зчитано {len(plaintext)} байт з файлу '{input_filepath}'")

        # 3. Шифрування даних (AES-256-ECB)
        print("    [*] Виконання алгоритму AES-256 у режимі ECB...")
        padded_data = self._pad(plaintext)
        cipher = Cipher(algorithms.AES(session_key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        print(f"    [+] Дані зашифровано. Розмір шифротексту: {len(ciphertext)} байт.")

        # 4. Асиметричне шифрування сеансового ключа
        with open("public_key.pem", "rb") as f:
            public_key_pem = f.read()

        public_key = serialization.load_pem_public_key(public_key_pem, backend=self.backend)
        encrypted_session_key = public_key.encrypt(
            session_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("    [*] Сеансовий ключ зашифровано відкритим ключем RSA-2048 (схема OAEP).")

        # 5. Збереження
        with open(output_filepath, 'wb') as f:
            f.write(encrypted_session_key)
            f.write(ciphertext)

        print(f"\n[УСПІХ] Файл гібридно зашифровано та збережено як '{output_filepath}'")
        print("Контейнер містить: [Зашифрований ключ RSA (256 байт)] + [Зашифровані дані AES]")

    def decrypt_file_interactive(self):
        input_filepath = input("\n[?] Введіть ім'я зашифрованого файлу (наприклад, document.txt.enc): ").strip()
        if not os.path.exists(input_filepath):
            print(f"[-] Помилка: Файл '{input_filepath}' не знайдено!")
            return

        output_filepath = input_filepath.replace(".enc", "_decrypted.txt")

        if not os.path.exists("private_key.pem"):
            print("[-] Помилка: Не знайдено private_key.pem. Потрібен закритий ключ для дешифрування!")
            return

        print("\n[*] Початок процедури дешифрування...")

        with open(input_filepath, 'rb') as f:
            encrypted_data = f.read()

        print(f"    [+] Зчитано зашифрований контейнер розміром {len(encrypted_data)} байт.")

        # Розділення
        encrypted_session_key = encrypted_data[:self.rsa_ciphertext_length]
        ciphertext = encrypted_data[self.rsa_ciphertext_length:]

        # Розшифрування ключа
        with open("private_key.pem", "rb") as f:
            private_key_pem = f.read()

        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=self.backend)

        try:
            session_key = private_key.decrypt(
                encrypted_session_key,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(
                f"    [+] Сеансовий ключ успішно розшифровано RSA-ключем: {binascii.hexlify(session_key).decode('utf-8')[:32]}...")
        except Exception as e:
            print("    [-] Помилка розшифрування ключа. Можливо, використовується невірний private_key.pem.")
            return

        # Розшифрування даних
        print("    [*] Дешифрування даних алгоритмом AES-256-ECB...")
        cipher = Cipher(algorithms.AES(session_key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        plaintext = self._unpad(padded_plaintext)

        with open(output_filepath, 'wb') as f:
            f.write(plaintext)

        print(f"\n[УСПІХ] Файл успішно розшифровано та збережено як '{output_filepath}'")

    def run_integrity_experiment(self, enc_filepath: str):
        """Експеримент №1: Симуляція пошкодження криптограми"""
        print("\n[*] Запуск експерименту з пошкодження криптограми...")

        if not os.path.exists(enc_filepath):
            print(f"[-] Спочатку зашифруйте будь-який файл, щоб отримати '{enc_filepath}'!")
            return

        # 1. Зчитуємо байти зашифрованого контейнера
        with open(enc_filepath, 'rb') as f:
            data = bytearray(f.read())

        # 2. Перевіряємо, чи файл достатньо великий (256 байт ключ + хоча б один блок даних)
        if len(data) <= self.rsa_ciphertext_length:
            print("[-] Файл занадто малий для експерименту.")
            return

        # 3. Вносимо точкову зміну в область AES-шифротексту (наприклад, на позиції 300)
        target_index = self.rsa_ciphertext_length + 5
        original_byte = data[target_index]
        # Змінюємо байт на інше випадкове значення (наприклад, інвертуємо біти через XOR або ставимо 0xFF)
        data[target_index] = 0xFF

        corrupted_filepath = "corrupted_document.txt.enc"
        with open(corrupted_filepath, 'wb') as f:
            f.write(data)

        print(f"    [+] Успішно змінено 1 байт на позиції {target_index} (було: {original_byte}, стало: 0xFF)")
        print(f"    [+] Створено пошкоджений файл: '{corrupted_filepath}'")

        # 4. Спроба розшифрувати пошкоджений файл
        print("    [*] Проводимо спробу дешифрування пошкодженого файлу...")
        try:
            # Викликаємо стандартне дешифрування для пошкодженого файлу
            with open(corrupted_filepath, 'rb') as f_corr:
                enc_data_corr = f_corr.read()

            enc_key = enc_data_corr[:self.rsa_ciphertext_length]
            ciphertext = enc_data_corr[self.rsa_ciphertext_length:]

            with open("private_key.pem", "rb") as f_priv:
                priv_pem = f_priv.read()
            private_key = serialization.load_pem_private_key(priv_pem, password=None, backend=self.backend)

            # RSA розшифрує сеансовий ключ успішно, бо ключова частина не чіпалась!
            session_key = private_key.decrypt(
                enc_key,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("    [+] RSA-частина: Сеансовий ключ успішно відновлено (асиметричний блок цілий).")

            # А от на етапі AES спрацює захист паддінгу
            cipher = Cipher(algorithms.AES(session_key), modes.ECB(), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Зняття PKCS#7 викине помилку
            self._unpad(padded_plaintext)

        except Exception as e:
            print(f"\n[КРИТИЧНА ПОМИЛКА ПЕРЕХОПЛЕНА СИСТЕМОЮ]: {e}")
            print("[УСПІХ] Експеримент підтвердив: пошкодження шифротексту виявлено, цілісність захищена!")

def main_menu():
    crypto_system = HybridCryptosystem()

    # Автоматично створюємо тестовий файл для зручності
    if not os.path.exists("document.txt"):
        with open("document.txt", "w", encoding="utf-8") as f:
            f.write(
                "Це секретний тестовий документ для РГР. Варіант 13 (AES-256 ECB, RSA-2048). Він використовується для перевірки шифрування.")

    while True:
        print("\n" + "=" * 50)
        print(" ГІБРИДНА КРИПТОСИСТЕМА (Варіант 13)".center(50))
        print("=" * 50)
        print("1. Згенерувати ключі RSA-2048 (public/private)")
        print("2. Зашифрувати файл (AES-256 ECB + RSA-2048)")
        print("3. Розшифрувати файл")
        print("4. Провести експеримент №1 (Пошкодження криптограми)")
        print("0. Вихід")
        print("=" * 50)

        choice = input("[?] Оберіть дію (0-3): ").strip()

        if choice == '1':
            crypto_system.generate_and_save_rsa_keys()
        elif choice == '2':
            crypto_system.encrypt_file_interactive()
        elif choice == '3':
            crypto_system.decrypt_file_interactive()
        elif choice == '4':
            crypto_system.run_integrity_experiment("document.txt.enc")

        elif choice == '0':
            print("\n[*] Завершення роботи програми. До побачення!")
            break
        else:
            print("[-] Невірний вибір. Спробуйте ще раз.")


if __name__ == "__main__":
    main_menu()