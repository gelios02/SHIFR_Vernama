```markdown
# 🔐 Stream Ciphers Utility

**Stream Ciphers Utility** — это консольное приложение на Python для демонстрации работы простых потоковых шифров. Программа позволяет:

- Генерировать файлы со случайными данными (с использованием стандартного генератора или LCG).
- Шифровать и расшифровывать файлы с помощью **шифра Вернама** (XOR-операция между двумя файлами).
- Шифровать и расшифровывать файлы с помощью простейшей реализации **RC4**.
- Просматривать содержимое бинарных файлов (в виде UTF-8 или HEX).

> **Важно:** Все операции проводятся в бинарном режиме. При шифровании/расшифровке ожидается, что длина файла-ключа совпадает (или не меньше) с длиной исходного файла.

---

## 📂 Структура проекта

```
SHIFR_Vernama/
├── app.py           # Основной скрипт с кодом (например, stream_ciphers.py)
├── README.md                # Этот файл
└── (сгенерированные файлы)   # Примеры: key.bin, cipher.bin, secret.bin, и т.д.
```

---

## 🚀 Установка и запуск

1. **Клонируйте репозиторий:**
   ```bash
   git clone https://github.com/your-username/SHIFR_Vernama.git
   cd SHIFR_Vernama
   ```

2. **Запустите приложение:**
   ```bash
   python app.py
   ```
   (Убедитесь, что у вас установлен Python 3.)

---

## 🎮 Как пользоваться программой

После запуска приложения в консоли появляется меню. Ниже приведён пример пользовательского сценария (user case):

### Меню программы

```
===== МЕНЮ =====
1. Сгенерировать файл случайных символов
2. Шифр Вернама (XOR двух файлов)
3. RC4: Шифрование/расшифрование файла
4. Просмотр содержимого бинарного файла
5. Выход
```

> **Замечание:** В представленном коде используются следующие варианты:
> - **Опция 1:** Генерация файла случайных символов  
> - **Опция 2:** Шифрование/расшифрование с помощью шифра Вернама  
> - **Опция 3:** Шифрование/расшифрование с помощью RC4  
> - **Опция 4:** Просмотр содержимого бинарного файла  
> - **Опция 5:** Выход из программы  
> _В коде, согласно логике, опция "4" вызывает просмотр бинарного файла, а опция "5" — завершение программы. При использовании меню убедитесь, что вы вводите правильные номера._

---

### Пример сценариев использования

#### 1. Генерация файла случайных символов
- **Ввод:**  
  - Имя файла: `key.bin`
  - Размер (в байтах): `100`
  - Использовать LCG? (y/n): `n`
- **Вывод:**  
  Программа создаёт файл `key.bin` размером 100 байт со случайными данными.

#### 2. Шифрование/расшифрование с помощью шифра Вернама (XOR)
- **Шаг 1:** Подготовьте файл с открытым текстом, например `secret.txt` (создайте его с помощью любого текстового редактора, впишите "Hello, World!" и сохраните).
- **Шаг 2:** Используйте опцию 2:
  - Введите путь к открытому файлу: `secret.txt`
  - Введите путь к файлу-ключу: `key.bin` (файл, созданный на шаге 1)
  - Введите имя выходного файла: `cipher.bin`
- **Вывод:**  
  Файл `cipher.bin` будет содержать зашифрованный текст.  
  Для расшифрования запустите опцию 2 ещё раз, указав вместо `secret.txt` файл `cipher.bin` и тот же ключ `key.bin`; результат запишется в другой файл (например, `recovered.txt`), который совпадёт с исходным `secret.txt`.

#### 3. Шифрование/расшифрование с помощью RC4
- **Ввод:**  
  - Ключ (строка): например, `mysecretkey`
  - Путь к входному файлу: `secret.txt`
  - Имя выходного файла: `cipher_rc4.bin`
- **Вывод:**  
  Файл `cipher_rc4.bin` будет содержать результат RC4-шифрования.  
  Чтобы расшифровать, запустите опцию 3, используя тот же ключ и в качестве входного файла `cipher_rc4.bin`; на выходе получите восстановленный файл.

#### 4. Просмотр содержимого бинарного файла
- **Ввод:**  
  Введите путь к бинарному файлу (например, `secret.bin` или любой сгенерированный файл).
- **Вывод:**  
  Программа попытается декодировать файл как UTF-8. Если декодирование успешно, будет выведен читаемый текст; если нет, выведется HEX-представление.

#### 5. Выход
- Выберите соответствующую опцию (например, `6` или `5` в зависимости от реализации) для завершения работы программы.

---

## 💡 Дополнительные замечания

- **Пути к файлам:**  
  Если файлы находятся в одной папке с программой, можно указывать просто их имена (например, `key.bin`, `secret.txt`). Если они лежат в других директориях, указывайте относительный или абсолютный путь.

- **Бинарные файлы:**  
  Обратите внимание, что зашифрованные файлы и файлы с случайными данными могут отображаться как «мусор» в текстовых редакторах. Для просмотра используйте встроенную опцию просмотра или специализированные HEX-редакторы (например, [Hex Editor](https://marketplace.visualstudio.com/items?itemName=ms-vscode.hexeditor) для VS Code).


