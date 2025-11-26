import { t } from 'elysia';

// Новое: DTO для генерации ключа с параметром size
export const GenerateAesKeyQuery = t.Object({
    size: t.Optional(t.Numeric({ default: 256 }))
});

export const EncryptBody = t.Object({
    method: t.Union([t.Literal('AES'), t.Literal('RSA'), t.Literal('ECC')]),
    text: t.String(),
    key: t.Optional(t.String()),        // AES key (base64)
    publicKey: t.Optional(t.String())   // RSA/ECC public key
});

export const DecryptBody = t.Object({
    method: t.Union([t.Literal('AES'), t.Literal('RSA'), t.Literal('ECC')]),
    encryptedText: t.String(),
    key: t.Optional(t.String()),        // AES key (base64)
    privateKey: t.Optional(t.String())  // RSA/ECC private key
});

// Response DTOs
export const EncryptResponse = t.Object({
    encryptedText: t.String(),
    method: t.String(),
    executionTimeMs: t.Number(),
});

export const DecryptResponse = t.Object({
    decryptedText: t.String(),
    method: t.String(),
    executionTimeMs: t.Number(),
});

export const AesKeyResponse = t.Object({
    key: t.String()
});

export const AsymKeyResponse = t.Object({
    publicKey: t.String(),
    privateKey: t.String()
});