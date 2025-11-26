import { randomBytes, createCipheriv, createDecipheriv, publicEncrypt, privateDecrypt, generateKeyPairSync, createPublicKey, createPrivateKey, diffieHellman, createHash } from 'crypto';

export class EncryptionService {

    // --- AES ---
    generateAesKey(bits: number): { key: string } {
        // 128 bits = 16 bytes, 192 bits = 24 bytes, 256 bits = 32 bytes
        const bytes = bits / 8;

        // Валидация: поддерживаем только стандартные размеры AES
        if (![16, 24, 32].includes(bytes)) {
            throw new Error('Invalid key size. Use 128, 192 or 256 bits.');
        }

        const key = randomBytes(bytes).toString('base64');
        return { key };
    }

    encryptAes(text: string, keyBase64: string): { encryptedText: string, executionTimeMs: number } {
        const start = performance.now();

        const key = Buffer.from(keyBase64, 'base64');
        const iv = randomBytes(16); // IV всегда 16 байт для AES (размер блока)

        // Автоматически определяем алгоритм по длине ключа
        const algo = this.getAesAlgo(key.length);

        const cipher = createCipheriv(algo, key, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        // Формат: IV:Ciphertext
        const result = iv.toString('hex') + ':' + encrypted;

        const end = performance.now();
        return { encryptedText: result, executionTimeMs: end - start };
    }

    decryptAes(encryptedText: string, keyBase64: string): { decryptedText: string, executionTimeMs: number } {
        const start = performance.now();

        const parts = encryptedText.split(':');
        if (parts.length !== 2) throw new Error('Invalid encrypted text format. Expected IV:Ciphertext');

        const iv = Buffer.from(parts[0], 'hex');
        const encryptedData = parts[1];
        const key = Buffer.from(keyBase64, 'base64');

        const algo = this.getAesAlgo(key.length);

        const decipher = createDecipheriv(algo, key, iv);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        const end = performance.now();
        return { decryptedText: decrypted, executionTimeMs: end - start };
    }

    // Вспомогательная функция для выбора алгоритма
    private getAesAlgo(byteLength: number): string {
        switch (byteLength) {
            case 16: return 'aes-128-cbc';
            case 24: return 'aes-192-cbc';
            case 32: return 'aes-256-cbc';
            default: throw new Error(`Invalid AES key length: ${byteLength} bytes (${byteLength*8} bits). Expected 128, 192, or 256 bits.`);
        }
    }

    // --- RSA ---
    generateRsaKeys(): { publicKey: string; privateKey: string } {
        const { publicKey, privateKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        return { publicKey, privateKey };
    }

    encryptRsa(text: string, publicKey: string): { encryptedText: string, executionTimeMs: number } {
        const start = performance.now();
        const buffer = Buffer.from(text, 'utf8');
        const encrypted = publicEncrypt(publicKey, buffer);
        const end = performance.now();
        return { encryptedText: encrypted.toString('base64'), executionTimeMs: end - start };
    }

    decryptRsa(encryptedText: string, privateKey: string): { decryptedText: string, executionTimeMs: number } {
        const start = performance.now();
        const buffer = Buffer.from(encryptedText, 'base64');
        const decrypted = privateDecrypt(privateKey, buffer);
        const end = performance.now();
        return { decryptedText: decrypted.toString('utf8'), executionTimeMs: end - start };
    }

    // --- ECC ---
    generateEccKeys(): { publicKey: string; privateKey: string } {
        // Используем стандартную кривую P-256 (secp256r1)
        const { publicKey, privateKey } = generateKeyPairSync('ec', {
            namedCurve: 'prime256v1',
            publicKeyEncoding: { type: 'spki', format: 'der' },
            privateKeyEncoding: { type: 'pkcs8', format: 'der' }
        });

        // Возвращаем в HEX для удобства отображения в UI
        return {
            publicKey: publicKey.toString('hex'),
            privateKey: privateKey.toString('hex')
        };
    }

    encryptEcc(text: string, recipientPublicKeyHex: string): { encryptedText: string, executionTimeMs: number } {
        const start = performance.now();

        // 1. Восстанавливаем публичный ключ получателя
        const recipientKey = createPublicKey({
            key: Buffer.from(recipientPublicKeyHex, 'hex'),
            format: 'der',
            type: 'spki'
        });

        // 2. Генерируем временную (эфимерную) пару ключей
        const ephemeral = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

        // 3. ECDH: Вычисляем общий секрет
        const sharedSecret = diffieHellman({
            privateKey: ephemeral.privateKey,
            publicKey: recipientKey
        });

        // 4. Деривация ключа (простой SHA-256 от секрета) -> получаем AES ключ
        const aesKey = createHash('sha256').update(sharedSecret).digest();

        // 5. Шифруем сообщение с помощью AES-256-CBC
        const iv = randomBytes(16);
        const cipher = createCipheriv('aes-256-cbc', aesKey, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        // 6. Пакуем: Публичный ключ отправителя + IV + Шифртекст
        const ephemeralPubHex = ephemeral.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
        const payload = `${ephemeralPubHex}|${iv.toString('hex')}|${encrypted}`;

        const end = performance.now();
        return { encryptedText: payload, executionTimeMs: end - start };
    }

    decryptEcc(payload: string, privateKeyHex: string): { decryptedText: string, executionTimeMs: number } {
        const start = performance.now();

        const parts = payload.split('|');
        if (parts.length !== 3) throw new Error('Invalid ECC payload format.');

        const [ephemeralPubHex, ivHex, encryptedHex] = parts;

        // 1. Восстанавливаем ключи
        const privateKey = createPrivateKey({
            key: Buffer.from(privateKeyHex, 'hex'),
            format: 'der',
            type: 'pkcs8'
        });
        const ephemeralKey = createPublicKey({
            key: Buffer.from(ephemeralPubHex, 'hex'),
            format: 'der',
            type: 'spki'
        });

        // 2. ECDH: Восстанавливаем тот же общий секрет
        const sharedSecret = diffieHellman({
            privateKey: privateKey,
            publicKey: ephemeralKey
        });

        // 3. Получаем тот же AES ключ
        const aesKey = createHash('sha256').update(sharedSecret).digest();

        // 4. Расшифровываем
        const decipher = createDecipheriv('aes-256-cbc', aesKey, Buffer.from(ivHex, 'hex'));
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        const end = performance.now();
        return { decryptedText: decrypted, executionTimeMs: end - start };
    }
}