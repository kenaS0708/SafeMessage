# Импорт библиотек
import asyncio
import json
import sqlite3
import sys
from asyncio import Lock
from asyncore import loop

import socketio
from deep_translator import GoogleTranslator
from telethon import TelegramClient, events, errors, functions
from telethon.events import NewMessage

import threading
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from telethon.tl.types import User, Channel
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout, Bidirectional
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import load_model
from translate import Translator
import os
from telethon.events import NewMessage
import pickle
from quart import Quart, jsonify, request, Response
import logging
import base64
from cryptography.fernet import Fernet
import chardet  # 📌 Определит кодировку файла
import joblib
from vosk import Model, KaldiRecognizer
import wave
from pydub import AudioSegment
import aiohttp
import time
import psutil  # Для работы с процессами

def load_encryption_key():
    key_path = "encryption_key.key"
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    return key

# Инициализация шифра
encryption_key = load_encryption_key()
cipher = Fernet(encryption_key)

chat_updates = {}  # Хранит время последнего обновления чатов


def encrypt_session_file(file_path):
    try:
        with open(file_path, "rb") as file:
            data = file.read()

        # Если файл уже зашифрован, не трогаем его
        if not data.startswith(b"SQLite format 3"):
            print(f"✅ Файл {file_path} уже зашифрован, пропускаем")
            return

        encrypted_data = cipher.encrypt(data)

        with open(file_path, "wb") as file:
            file.write(encrypted_data)

        print(f"✅ Файл {file_path} успешно зашифрован")

    except Exception as e:
        print(f"❌ Ошибка при шифровании файла {file_path}: {e}")

import os

import os
import time

def force_delete_file(file_path):
    """Удаляет файл, даже если он используется другим процессом."""
    retries = 5
    for i in range(retries):
        try:
            os.remove(file_path)
            print(f"✅ Файл {file_path} успешно удалён.")
            return
        except PermissionError:
            print(f"⚠️ Файл {file_path} занят другим процессом. Повторная попытка ({i+1}/{retries})...")
            time.sleep(1)  # Ждём 1 секунду и пробуем снова


def is_valid_session(file_path):
    """Проверяет, является ли файл сессии допустимой SQLite-базой."""
    if not os.path.exists(file_path):
        print(f"⚠️ Файл {file_path} отсутствует.")
        return False

    try:
        # ✅ Проверяем заголовок файла (SQLite формат 3)
        with open(file_path, "rb") as f:
            header = f.read(16)
        if not header.startswith(b"SQLite format 3"):
            print(f"⚠️ Файл {file_path} не является SQLite-базой.")
            return False

        # ✅ Открываем SQLite и проверяем работоспособность
        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check;")  # Проверяем целостность базы
        result = cursor.fetchone()
        conn.close()

        if result and result[0] == "ok":
            return True
        else:
            print(f"⚠️ Файл {file_path} повреждён (SQLite integrity check не пройден).")
            return False

    except sqlite3.DatabaseError as e:
        print(f"❌ Ошибка SQLite при проверке {file_path}: {e}")
        return False


def decrypt_session_file(file_path):
    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        # Если файл уже расшифрован, просто выходим
        if encrypted_data.startswith(b"SQLite format 3"):
            print(f"✅ Файл {file_path} уже расшифрован, пропускаем")
            return

        decrypted_data = cipher.decrypt(encrypted_data)

        with open(file_path, "wb") as file:
            file.write(decrypted_data)

        print(f"✅ Файл {file_path} успешно расшифрован")

    except Exception as e:
        print(f"❌ Ошибка при расшифровке файла {file_path}: {e}")


def init_db():
    conn = sqlite3.connect("dangerous_messages.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dangerous_messages (
            chat_id INTEGER NOT NULL,
            message_id INTEGER NOT NULL,
            reason TEXT,
            threat_type TEXT,
            PRIMARY KEY (chat_id, message_id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

app = Quart(__name__, static_folder="static")


locks = {}

chat_cache = {}

# Глобальный словарь для хранения опасных сообщений
dangerous_messages = {}

logging.basicConfig(level=logging.DEBUG)

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Создаем сервер Socket.IO
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')

# Создаем приложение ASGI для Socket.IO и связываем его с Quart
app_asgi = socketio.ASGIApp(sio, app)

# Telegram API параметры
API_ID = 28034410
API_HASH = '97de1536f327bbf14380a13e59a9a5be'
clients = {}

import speech_recognition as sr

async def startup():
    await load_existing_sessions()
    asyncio.create_task(cleanup_locks())
    asyncio.create_task(monitor_new_messages())


async def load_existing_sessions():
    session_files = [f for f in os.listdir('.') if f.startswith('session_') and f.endswith('.session')]

    for session_file in session_files:
        try:
            phone_number = session_file.replace('session_', '').replace('.session', '')

            print(f"[{phone_number}] 🔍 Автозагрузка сессии...")

            decrypt_session_file(session_file)  # ✅ Расшифровка перед загрузкой

            client = TelegramClient(session_file, API_ID, API_HASH)

            try:
                await client.connect()
            except Exception as e:
                logger.error(f"[{phone_number}] ❌ Ошибка подключения клиента, пробуем пересоздать: {e}")
                client = TelegramClient(session_file, API_ID, API_HASH)
                await client.connect()

            if await client.is_user_authorized():
                clients[phone_number] = client
                logger.info(f"[{phone_number}] ✅ Клиент загружен и подключен")
                add_message_handler(phone_number)  # ✅ Восстанавливаем обработчики сообщений
            else:
                logger.warning(f"[{phone_number}] ❌ Клиент не авторизован, удаляем сессию")
                os.remove(session_file)  # Удаляем битую сессию

            encrypt_session_file(session_file)  # ✅ Шифруем обратно

        except Exception as e:
            logger.error(f"[{phone_number}] ❌ Ошибка загрузки сессии: {e}")


async def monitor_new_messages():
    while True:
        try:
            if not clients:
                logger.warning("Нет подключенных клиентов. Убедитесь, что авторизация выполнена.")
            for phone_number, client in clients.items():
                if not client.is_connected():
                    logger.info(f"[{phone_number}] Переподключение клиента...")
                    await client.connect()

                logger.info(f"[{phone_number}] Слушаем новые сообщения...")
                add_message_handler(phone_number)

            await asyncio.sleep(5)  # Проверяем каждые 5 секунд
        except Exception as e:
            logger.error(f"Ошибка в monitor_new_messages: {e}")



def start_global_loop():
    asyncio.set_event_loop(global_loop)
    global_loop.run_forever()

global_loop = asyncio.new_event_loop()
threading.Thread(target=lambda: asyncio.set_event_loop(global_loop) or global_loop.run_forever(), daemon=True).start()
print(f"Глобальный event loop запущен: {global_loop.is_running()}")



async def download_audio(audio_url, save_path):
    """Скачивает аудиофайл по ссылке."""
    async with aiohttp.ClientSession() as session:
        async with session.get(audio_url) as response:
            if response.status == 200:
                with open(save_path, "wb") as f:
                    f.write(await response.read())
            else:
                raise Exception(f"Ошибка скачивания аудио: {response.status}")

import requests
import json
import asyncio


async def handle_voice_message(event, phone_number):
    try:
        sender = await event.get_sender()
        chat = await event.get_chat()
        message_id = event.message.id
        current_user = await clients[phone_number].get_me()

        if sender.id == current_user.id:
            return

        if isinstance(chat, Channel) and chat.broadcast:
            return

        if not event.message.voice:
            return

        # ✅ Скачиваем голосовое сообщение
        voice_path = await event.message.download_media()
        if not os.path.exists(voice_path):
            logger.error(f"❌ Ошибка: скачанный файл {voice_path} не найден.")
            return

        logger.info(f"✅ Файл {voice_path} успешно скачан.")

        # ✅ Распознаём речь
        transcribed_text = transcribe_audio(voice_path)

        if not transcribed_text:
            transcribed_text = "[Ошибка распознавания речи]"

        logger.info(f"📝 Расшифрованный текст: {transcribed_text}")

        # ✅ Анализируем текст на угрозы
        analysis_result = analyze_message_local(transcribed_text)

        is_phishing = analysis_result['phishing'] == 'Фишинговое сообщение'
        is_terrorism = analysis_result['terrorism'] == 'Террористическое сообщение'

        if is_phishing or is_terrorism:
            threat_type = "Фишинг" if is_phishing else "Терроризм"
            reason = "Phishing content detected" if is_phishing else "Terrorist content detected"
            save_dangerous_message(chat.id, message_id, reason, threat_type)

            logger.info(f"⚠️ Обнаружено опасное голосовое сообщение!")

            transcribed_text_result = "Голосовое сообщение: "+transcribed_text

            # ✅ Отправляем предупреждение на клиент
            await sio.emit(
                'dangerous_message',
                {
                    'phoneNumber': phone_number,
                    'chatId': chat.id,
                    'messageId': message_id,
                    'message': transcribed_text_result,
                    'analysis': {
                        'phishing': analysis_result['phishing'],
                        'terrorism': analysis_result['terrorism'],
                        'threatType': threat_type,
                        'reason': reason
                    }
                },
                namespace='/'
            )

    except Exception as e:
        logger.error(f"❌ Ошибка в обработке голосового сообщения: {e}")


# model = Model("model")
#
#
# AudioSegment.converter = r"C:\ProgramData\chocolatey\bin\ffmpeg.exe"


def convert_to_wav(audio_path: str) -> str:
    audio = AudioSegment.from_file(audio_path)
    wav_path = audio_path.replace(".oga", ".wav")
    audio.export(wav_path, format="wav")
    return wav_path


def transcribe_audio(audio_path: str) -> str:
    try:
        # Конвертируем файл в WAV, если это необходимо
        if not audio_path.endswith(".wav"):
            audio_path = convert_to_wav(audio_path)

        recognizer = sr.Recognizer()
        with sr.AudioFile(audio_path) as source:
            audio_data = recognizer.record(source)

        # Использование Google Web Speech API
        transcript = recognizer.recognize_google(audio_data, language="ru-RU")
        return transcript
    except sr.UnknownValueError:
        return "Не удалось распознать речь"
    except sr.RequestError as e:
        return f"Ошибка запроса: {e}"
    except Exception as e:
        return f"Ошибка: {e}"


phishing_model = load_model("phishing_detector.h5")
tokenizer = joblib.load("tokenizer.pkl")

# 1. Загрузим модель для терроризма (предполагаем, что она существует)
terror_model = load_model('message_classifier_terror.h5')
terror_tokenizer = joblib.load('tokenizer_terror.pkl')  # или аналогичный токенизатор для террористических сообщений

def detect_terrorism_message(message: str):
    # Токенизируем и преобразуем сообщение для модели терроризма
    transformed_msg = terror_tokenizer.texts_to_sequences([message])
    transformed_msg = pad_sequences(transformed_msg, maxlen=100)  # Приводим к нужной длине

    # Предсказываем вероятность терроризма
    prediction = terror_model.predict(transformed_msg)[0][0]
    return "Террористическое сообщение" if prediction > 0.5 else "Безопасное сообщение"


# Длина последовательности, которую использовали при обучении
MAX_SEQUENCE_LENGTH = 100  # Убедись, что это то же значение, что и при тренировке модели!

def translate_to_english(text):
    return GoogleTranslator(source='auto', target='en').translate(text)

# Функция предсказания фишинга
def detect_phishing_message(message: str):
    translated_msg = translate_to_english(message)  # Переводим перед анализом
    transformed_msg = tokenizer.texts_to_sequences([translated_msg])  # Токенизируем
    transformed_msg = pad_sequences(transformed_msg, maxlen=MAX_SEQUENCE_LENGTH)  # Приводим к нужной длине

    # Предсказываем вероятность фишинга
    prediction = phishing_model.predict(transformed_msg)[0][0]
    return "Фишинговое сообщение" if prediction > 0.5 else "Безопасное сообщение"

def analyze_message_local(message):
    result_phishing = detect_phishing_message(message)  # Проверяем на фишинг
    result_terrorism = detect_terrorism_message(message)  # Проверяем на терроризм

    # Возвращаем оба результата
    print(f"Фишинг: {result_phishing}, Терроризм: {result_terrorism}")
    return {"phishing": result_phishing, "terrorism": result_terrorism}


def save_dangerous_message(chat_id, message_id, reason, threat_type):
    conn = sqlite3.connect("dangerous_messages.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO dangerous_messages (chat_id, message_id, reason, threat_type)
        VALUES (?, ?, ?, ?)
    """, (chat_id, message_id, reason, threat_type))
    conn.commit()
    conn.close()


async def handle_new_message(event, phone_number):
    try:
        sender = await event.get_sender()
        chat = await event.get_chat()
        message_id = event.message.id
        current_user = await clients[phone_number].get_me()

        if sender.id == current_user.id or (isinstance(chat, Channel) and chat.broadcast):
            return

        # ✅ Фиксируем обновление чата
        chat_updates[chat.id] = time.time()

        # ✅ Определяем тип контента
        if event.message.voice:
            # Расшифровка голосового сообщения
            voice_path = await event.message.download_media()
            transcribed_text = transcribe_audio(voice_path) if voice_path else "[Ошибка распознавания речи]"
            message_text = f"Голосовое сообщение: {transcribed_text}"
        else:
            message_text = event.message.text or "[Пустое сообщение]"

        logger.info(f"📩 Обрабатываем сообщение (ID: {message_id}) в чате {chat.id}: {message_text}")

        # ✅ Проверка голосового сообщения на фишинг/терроризм
        is_dangerous = False
        threat_type = None
        reason = None
        analysis_data = {}

        if event.message.voice and transcribed_text:
            analysis_result = analyze_message_local(transcribed_text)
            is_phishing = analysis_result.get('phishing') == 'Фишинговое сообщение'
            is_terrorism = analysis_result.get('terrorism') == 'Террористическое сообщение'

            if is_phishing or is_terrorism:
                is_dangerous = True
                threat_type = "Фишинг" if is_phishing else "Терроризм"
                reason = "Phishing content detected" if is_phishing else "Terrorist content detected"
                save_dangerous_message(chat.id, message_id, reason, threat_type)

                analysis_data = {
                    'phishing': analysis_result['phishing'],
                    'terrorism': analysis_result['terrorism'],
                    'threatType': threat_type,
                    'reason': reason
                }

                await sio.emit(
                    'dangerous_message',
                    {
                        'phoneNumber': phone_number,
                        'chatId': chat.id,
                        'messageId': message_id,
                        'message': message_text,
                        'analysis': analysis_data
                    },
                    namespace='/'
                )

        logger.info(f"✅ Чат {chat.id} добавлен в `chat_updates` для обновлений.")

        # ✅ Отправка обновления чата в WebSocket с анализом угроз
        await sio.emit(
            'chat_update',
            {
                'phoneNumber': phone_number,
                'chatId': chat.id,
                'lastMessage': message_text,
                'timestamp': event.message.date.timestamp(),
                'messageId': message_id,
                'isDangerous': is_dangerous,  # Добавляем информацию о том, что сообщение опасное
                'analysis': analysis_data  # Отправляем данные анализа угроз
            },
            namespace='/'
        )

        # ✅ Отправка нового сообщения в WebSocket-комнату
        message_data = {
            "chatId": chat.id,
            "messageId": message_id,
            "sender": sender.id,
            "text": message_text,
            "timestamp": event.message.date.timestamp(),
            "isDangerous": is_dangerous,  # Добавляем информацию о том, что сообщение опасное
            "analysis": analysis_data  # Отправляем данные анализа угроз
        }

        clients_in_room = sio.manager.rooms.get(str(chat.id), set())
        if clients_in_room:
            await sio.emit("message_received", message_data, room=str(chat.id))
        else:
            logger.warning(f"⚠️ Нет активных клиентов в комнате {chat.id}, сообщение не отправлено.")

    except Exception as e:
        logger.error(f"❌ Ошибка в обработчике нового сообщения: {e}")



def add_message_handler(phone_number):
    try:
        if phone_number not in clients:
            raise Exception(f"Клиент для {phone_number} не существует")

        client = clients[phone_number]

        # Удаляем старые обработчики, чтобы избежать дублирования
        client.remove_event_handler(handle_new_message)
        client.remove_event_handler(handle_voice_message)  # Удаляем старый обработчик

        # Добавляем обработчик для текстовых сообщений
        client.add_event_handler(
            lambda event: asyncio.create_task(handle_new_message(event, phone_number)),
            NewMessage()
        )

        # Добавляем обработчик для голосовых сообщений
        client.add_event_handler(
            lambda event: asyncio.create_task(handle_voice_message(event, phone_number)),
            events.NewMessage(incoming=True, pattern=None)
        )

        logger.info(f"✅ Обработчики событий добавлены для {phone_number}")

    except Exception as e:
        logger.error(f"Ошибка при добавлении обработчиков событий: {e}")



async def authenticate_and_send_code(phone_number):
    lock = await get_lock(phone_number)
    async with lock:
        session_file = f"session_{phone_number}.session"

        # Удаляем старый клиент, если он есть
        if phone_number in clients:
            await clients[phone_number].disconnect()
            client = clients.pop(phone_number, None)
            if client:
                await client.disconnect()  # ✅ Отключаем клиента
                await client.disconnect()

        try:
            # Удаляем старую сессию, если она есть
            if os.path.exists(session_file):
                time.sleep(1)
                print(f"[{phone_number}] Удаление старого файла сессии...")
                os.remove(session_file)

            client = TelegramClient(
                session_file, API_ID, API_HASH, loop=loop,
                system_version="4.16.30-vxCUSTOM", device_model="Android", app_version="1.0.0"
            )
            await client.connect()
            await client.send_code_request(phone_number)

            clients[phone_number] = client
            print(f"[{phone_number}] Код успешно отправлен!")

        except Exception as e:
            print(f"[{phone_number}] Ошибка отправки кода: {e}")

async def authenticate_and_verify_code(phone_number, code):
    lock = await get_lock(phone_number)
    async with lock:
        session_file = f"session_{phone_number}.session"
        if not os.path.exists(session_file):
            print(f"[{phone_number}] Файл сессии отсутствует.")
            return False  # <== Возвращаем False

        decrypt_session_file(session_file)

        client = clients.get(phone_number)
        if not client:
            print(f"[{phone_number}] Клиент не найден.")
            return False  # <== Возвращаем False

        if await client.is_user_authorized():
            print(f"[{phone_number}] Уже авторизован.")
            return True  # <== Возвращаем True

        try:
            print(f"[{phone_number}] Верификация кода...")
            await client.sign_in(phone=phone_number, code=code)

            if await client.is_user_authorized():
                print(f"[{phone_number}] Успешная авторизация.")
                add_message_handler(phone_number)
                return True  # <== Возвращаем True
            else:
                print(f"[{phone_number}] Авторизация не удалась.")
                return False  # <== Возвращаем False

        except errors.PhoneCodeInvalidError:
            print(f"[{phone_number}] Неверный код!")
            return False  # <== Возвращаем False


@app.route('/verify-code', methods=['POST'])
async def verify_code():
    try:
        data = await request.get_json()
        phone_number = data.get('phoneNumber')
        code = data.get('code')

        if not phone_number or not code:
            return jsonify({"success": False, "error": "Both phoneNumber and code are required"}), 400

        success = await authenticate_and_verify_code(phone_number, code)

        if success:
            return jsonify({"success": True, "message": "Code verified successfully"}), 200
        else:
            return jsonify({"success": False, "error": "Invalid code"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


async def get_lock(phone_number):
    if phone_number not in locks:
        locks[phone_number] = Lock()
    return locks[phone_number]

async def cleanup_locks(interval=3600):
    while True:
        await asyncio.sleep(interval)  # Ждем заданный интервал
        to_remove = []
        for phone_number, lock in locks.items():
            if phone_number not in clients:  # Если клиента нет в активных
                to_remove.append(phone_number)
        for phone_number in to_remove:
            await remove_lock(phone_number)
        print(f"Очистка завершена. Удалено {len(to_remove)} блокировок.")

async def startup():
    asyncio.create_task(cleanup_locks())

async def remove_lock(phone_number):
    if phone_number in locks:
        del locks[phone_number]
        print(f"[{phone_number}] Блокировка удалена.")


@app.route('/send-code', methods=['POST'])
async def send_code():
    try:
        data = await request.get_json()
        phone_number = data.get('phoneNumber')
        if not phone_number:
            return jsonify({"error": "phoneNumber is required"}), 400

        await authenticate_and_send_code(phone_number)
        return jsonify({"message": "Code sent successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/get-chats', methods=['GET'])
async def get_chats():
    phone_number = request.args.get('phoneNumber')

    if not phone_number:
        return jsonify({"error": "Missing phoneNumber parameter"}), 400

    session_file = f"session_{phone_number}.session"

    if phone_number not in clients:
        logger.warning(f"[{phone_number}] ⚠️ Клиент отсутствует в памяти. Пробуем загрузить...")
        await load_existing_sessions()

    if phone_number not in clients:
        logger.error(f"[{phone_number}] ❌ Клиент не найден после загрузки! Пробуем пересоздать...")

        try:
            decrypt_session_file(session_file)

            clients[phone_number] = TelegramClient(session_file, API_ID, API_HASH)
            await clients[phone_number].connect()

            if not await clients[phone_number].is_user_authorized():
                logger.error(f"[{phone_number}] ❌ Повторная авторизация не удалась")
                os.remove(session_file)
                return jsonify({"error": "Session not found, please re-authenticate"}), 400

            add_message_handler(phone_number)
            encrypt_session_file(session_file)

        except Exception as e:
            logger.error(f"[{phone_number}] ❌ Ошибка при пересоздании клиента: {e}")
            return jsonify({"error": "Session recovery failed"}), 400

    client = clients[phone_number]

    logger.info(f"[{phone_number}] 📞 Получение списка чатов...")
    new_chats = await get_unknown_chats(client)

    # 🔥 Логируем, какие чаты передаем в клиент

    return jsonify(new_chats), 200


def safely_remove_file(file_path):
    """
    Безопасное удаление файла. Проверяет, доступен ли файл для удаления.
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Файл {file_path} успешно удалён.")
    except PermissionError as e:
        print(f"Ошибка при удалении файла {file_path}: {e}")
    except Exception as e:
        print(f"Неизвестная ошибка при удалении файла {file_path}: {e}")


@app.route('/get-updated-chats', methods=['GET'])
async def get_updated_chats():
    phone_number = request.args.get('phoneNumber')

    if not phone_number:
        return jsonify({"error": "Missing phoneNumber parameter"}), 400

    client = clients.get(phone_number)
    if not client:
        return jsonify({"error": "Client not found"}), 400

    updated_chat_ids = list(chat_updates.keys())  # Берем ID обновленных чатов
    updated_chats = await get_specific_chats(client, updated_chat_ids)
    chat_updates.clear()  # Очищаем список обновленных чатов

    logger.info(f"[{phone_number}] 📤 Отправляем в приложение обновленные чаты: {updated_chats}")

    return jsonify(updated_chats), 200


async def get_specific_chats(client, chat_ids):
    """Получает информацию только о чатах, которые обновились."""
    try:
        logger.info(f"🔍 Запрос обновленных чатов: {chat_ids}")

        all_chats = await client.get_dialogs()
        logger.info(f"📜 Всего чатов от Telegram: {len(all_chats)}")

        updated_chats = [chat for chat in all_chats if str(chat.id) in chat_ids]
        logger.info(f"✅ Найдено обновленных чатов: {len(updated_chats)}")

        result = [
            {
                "chat_id": str(chat.id),
                "chat_name": chat.title,
                "last_message": chat.message.text if chat.message else "Нет сообщений",
                "avatar": None,  # Можно добавить обработку аватарок
                "last_message_timestamp": chat.message.date.timestamp() if chat.message else 0,
                "unreadCount": chat.unread_count
            }
            for chat in updated_chats
        ]

        logger.info(f"📤 Финальный список отправки: {result}")
        return result

    except Exception as e:
        logger.error(f"❌ Ошибка при получении обновленных чатов: {e}")
        return []


async def get_unknown_chats(client):
    """Получает список чатов и загружает данные о них параллельно."""
    try:
        dialogs = await client.get_dialogs()
        logger.info(f"Найдено {len(dialogs)} диалогов")

        unknown_chats = []
        max_message_length = 50

        async def process_dialog(dialog):
            """Обрабатывает один диалог."""
            if not dialog.is_user:
                return None

            entity = await client.get_entity(dialog.id)
            if entity.contact or entity.bot or dialog.is_channel:
                return None

            # Кеширование данных
            if dialog.id in chat_cache:
                return {
                    **chat_cache[dialog.id],
                    "last_message": format_message(dialog.message, max_message_length),
                    "last_message_timestamp": dialog.message.date.timestamp() if dialog.message else 0,
                }

            # Загрузка аватарки
            photo = None
            if entity.photo:
                try:
                    raw_photo = await client.download_profile_photo(entity.id, file=bytes)
                    if raw_photo:
                        photo = base64.b64encode(raw_photo).decode('utf-8')
                except Exception as e:
                    logger.warning(f"Не удалось загрузить аватарку для {entity.id}: {e}")

            # Формирование данных
            chat_data = {
                "chat_id": dialog.id,
                "chat_name": entity.first_name or "Неизвестно",
                "avatar": photo,
            }
            chat_cache[dialog.id] = chat_data

            return {
                **chat_data,
                "last_message": format_message(dialog.message, max_message_length),
                "last_message_timestamp": dialog.message.date.timestamp() if dialog.message else 0,
            }

        # Параллельная обработка всех диалогов
        results = await asyncio.gather(*(process_dialog(dialog) for dialog in dialogs))
        unknown_chats = [res for res in results if res]

        return unknown_chats

    except Exception as e:
        logger.error(f"Ошибка в get_unknown_chats: {e}")
        raise

def format_message(message, max_length):
    """Форматирует текст сообщения."""
    if not message:
        return "Нет сообщений"
    text = message.message or "Нет текста"
    return text[:max_length] + "..." if len(text) > max_length else text

def is_message_dangerous(chat_id, message_id):
    conn = sqlite3.connect("dangerous_messages.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT reason, threat_type FROM dangerous_messages
        WHERE chat_id = ? AND message_id = ?
    """, (chat_id, message_id))
    result = cursor.fetchone()
    conn.close()
    return result

VOICE_FOLDER = "static/voices"
os.makedirs(VOICE_FOLDER, exist_ok=True)

@app.route('/chat/<chat_id>/history', methods=['GET'])
async def get_chat_history(chat_id):
    phone_number = request.args.get('phoneNumber')

    logging.info(f"📥 Получен запрос: chat_id={chat_id}, phoneNumber={phone_number}")

    if not phone_number:
        return jsonify({"error": "Missing phoneNumber parameter"}), 400

    if phone_number not in clients:
        logging.warning(f"⚠️ Клиент {phone_number} отсутствует в памяти. Пробуем загрузить...")
        session_file = f"session_{phone_number}.session"

        try:
            decrypt_session_file(session_file)  # Расшифровка сессии, если нужно

            client = TelegramClient(session_file, API_ID, API_HASH)
            await client.connect()

            if await client.is_user_authorized():
                clients[phone_number] = client
                logging.info(f"✅ Клиент {phone_number} успешно загружен и авторизован")
            else:
                logging.error(f"❌ Клиент {phone_number} не авторизован после загрузки")
                return jsonify({"error": "Client is not authenticated"}), 401

            encrypt_session_file(session_file)  # Зашифровка сессии

        except Exception as e:
            logging.error(f"❌ Ошибка загрузки клиента {phone_number}: {e}")
            return jsonify({"error": "Session recovery failed"}), 400

    client = clients[phone_number]

    if not await client.is_user_authorized():
        logging.error(f"❌ Ошибка: Клиент {phone_number} не авторизован")
        return jsonify({"error": "Client is not authenticated"}), 401

    current_user = await client.get_me()
    messages = []
    logging.info(f"✅ Загружаем сообщения чата {chat_id} для {phone_number}...")

    # 🔹 Загружаем диалоги, чтобы обновить кэш
    await client.get_dialogs()

    # 🔹 Пробуем получить сущность чата
    try:
        entity = await client.get_entity(int(chat_id))
    except ValueError:
        try:
            entity = await client.get_input_entity(int(chat_id))
        except Exception as e:
            logging.warning(f"⚠️ Чат {chat_id} не найден, пробуем добавить пользователя в контакты...")

            try:
                user = await client(functions.contacts.ResolveUsernameRequest(chat_id))
                entity = user.users[0] if user.users else None
            except Exception as e:
                logging.error(f"❌ Ошибка получения сущности чата {chat_id}: {e}")
                return jsonify({"error": "Invalid chat ID"}), 400

    # ✅ Загружаем сообщения
    async for message in client.iter_messages(entity, limit=100):
        message_text = message.message or ""
        timestamp = int(message.date.timestamp()) if message.date else None
        sender_id = message.sender_id

        # 🔹 Попытка загрузить данные о пользователе (если ошибка, пропускаем)
        try:
            chat_entity = await client.get_entity(sender_id)
            chat_name = chat_entity.title if hasattr(chat_entity, 'title') else chat_entity.first_name
            avatar_base64 = None

            if chat_entity.photo:
                avatar_bytes = await client.download_profile_photo(chat_entity, file=bytes)
                avatar_base64 = base64.b64encode(avatar_bytes).decode("utf-8")
        except Exception as e:
            logging.error(f"⚠️ Ошибка получения данных пользователя {sender_id}: {e}")
            chat_name = "Unknown"
            avatar_base64 = None

        # 🔹 Проверяем, является ли сообщение опасным
        danger_info = is_message_dangerous(chat_id, message.id)
        is_dangerous = danger_info is not None
        reason = danger_info[0] if danger_info else None
        threat_type = danger_info[1] if danger_info else None

        logging.info(f"📩 Message ID {message.id} - Date: {message.date}")

        # Определение типа сообщения
        if message.voice:
            message_type = "Voice"
        elif message.video:
            message_type = "Video"
        elif message.photo:
            message_type = "Pic"
        elif message.video_note:
            message_type = "VideoM"
        else:
            message_type = message.message.strip() if message.message else "Нет текста"

        messages.append({
            "id": message.id,
            "message": message_text,
            "isMine": sender_id == current_user.id,
            "avatar": avatar_base64,
            "chatId": chat_id,
            "chatName": chat_name,
            "isDangerous": is_dangerous,
            "reason": reason,
            "threatType": threat_type,
            "timestampchat": timestamp,
            "type": message_type,
        })

    logging.info(f"📤 Отправляем в приложение {len(messages)} сообщений.")
    return jsonify(messages), 200

@app.route('/block-contact', methods=['POST'])
async def block_contact_api():
    try:
        print("Запрос на /block-contact")
        data = await request.get_json()
        chat_id = data.get('chatId')  # Получаем chatId из запроса
        print(f"Получен chatId: {chat_id}")

        if not chat_id:
            return jsonify({"error": "chatId is required"}), 400

        # Логируем содержимое clients
        print("Содержимое clients:", clients.keys())

        # Выбираем первого доступного клиента (например, для текущего аккаунта)
        # Если нужно, можно уточнить, как выбрать подходящий клиент
        for phone_number, client in clients.items():
            print(f"Пробуем использовать клиента с номером {phone_number}")
            result = await block_contact(client, chat_id)
            if result:
                return jsonify({"message": f"Контакт с chatId {chat_id} заблокирован"}), 200

        # Если ни один клиент не подходит
        return jsonify({"error": "Не удалось найти подходящего клиента"}), 404

    except Exception as e:
        print(f"Ошибка: {e}")
        return jsonify({"error": str(e)}), 500


async def block_contact(client, chat_id):
    try:
        # Преобразуем chatId в объект InputPeer
        entity = await client.get_input_entity(int(chat_id))  # Преобразуем chatId в int, если это строка

        # Выполняем блокировку
        await client(functions.contacts.BlockRequest(entity))
        print(f"Контакт с chatId {chat_id} заблокирован.")
        return True
    except Exception as e:
        print(f"Ошибка при блокировке контакта с chatId {chat_id}: {e}")
        return False


@sio.on("join_chat")
async def join_chat(sid, chat_id):
    logger.info(f"🔌 Клиент {sid} пытается присоединиться к комнате {chat_id} (тип: {type(chat_id)})")

    if not isinstance(chat_id, str):
        logger.warning(f"⚠️ Ошибка: chat_id должен быть строкой, но получен {type(chat_id)}")
        return  # Если ID не строка, прерываем выполнение

    await sio.enter_room(sid, chat_id)  # ✅ Добавляем клиента

    all_rooms = sio.manager.rooms.get('/', {})  # ✅ Берем все комнаты на сервере
    clients_in_room = all_rooms.get(chat_id, {})  # ✅ Берем клиентов только из нужной комнаты
    logger.info(f"🔌 Все активные сокеты: {list(sio.manager.rooms['/'].keys())}")

    logger.info(f" Все комнаты после join: {all_rooms}")
    logger.info(f"📢 Клиенты в комнате {chat_id} после join: {clients_in_room.keys()}")  # 💡 Выводим `.keys()`

    if sid in clients_in_room:
        logger.info(f"✅ Клиент {sid} успешно добавился в комнату {chat_id}")
    else:
        logger.warning(f"⚠️ Клиент {sid} НЕ добавился в комнату {chat_id}!")

@sio.on('connect')
def on_connect(sid, environ):
    logger.info(f"🚪 Клиент {sid} подключился.")

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

@sio.on('disconnect')
def on_disconnect(sid):
    logger.info(f"🚪 Клиент {sid} отключился от сервера")
    # Проверим, что клиент действительно был в комнате
    for room in sio.manager.rooms:
        logger.info(f"Комната {room} имеет участников: {sio.manager.rooms[room]}")


@app.websocket('/updates')
async def updates():
    while True:
        await asyncio.sleep(1)  # Заглушка для поддержания соединения

if __name__ == '__main__':
    startup()  # Запускаем фоновые задачи

    import uvicorn
    uvicorn.run(app_asgi, host='0.0.0.0', port=5000)