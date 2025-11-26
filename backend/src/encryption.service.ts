import crypto from "crypto";
import { ec as EC } from "elliptic";
import { EncryptionMethod } from "./dto";

const ec = new EC("p256");

export function generateAesKey(): string {
  const key = crypto.randomBytes(32);
  return key.toString("base64");
}

export function encryptAes(plaintext: string, keyBase64: string): string {
  const key = Buffer.from(keyBase64, "base64");
  if (key.length !== 32) {
    throw new Error("AES key must be 32 bytes (base64-encoded).");
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const packed = Buffer.concat([iv, authTag, ciphertext]);
  return packed.toString("base64");
}

export function decryptAes(encryptedBase64: string, keyBase64: string): string {
  const key = Buffer.from(encryptedBase64 ? keyBase64 : "", "base64");
  if (key.length !== 32) {
    throw new Error("AES key must be 32 bytes (base64-encoded).");
  }
  const packed = Buffer.from(encryptedBase64, "base64");
  const iv = packed.subarray(0, 12);
  const authTag = packed.subarray(12, 28);
  const ciphertext = packed.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString("utf8");
}

export function generateRsaKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  return { publicKey, privateKey };
}

export function encryptRsa(plaintext: string, publicKeyPem: string): string {
  const buffer = Buffer.from(plaintext, "utf8");
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    },
    buffer
  );
  return encrypted.toString("base64");
}

export function decryptRsa(encryptedBase64: string, privateKeyPem: string): string {
  const buffer = Buffer.from(encryptedBase64, "base64");
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    },
    buffer
  );
  return decrypted.toString("utf8");
}

export function generateEccKeyPair(): { publicKey: string; privateKey: string } {
  const key = ec.genKeyPair();
  const publicKey = key.getPublic(true, "hex");
  const privateKey = key.getPrivate("hex");
  return { publicKey, privateKey };
}

export function encryptEcc(plaintext: string, recipientPublicKeyHex: string): string {
  if (!recipientPublicKeyHex) throw new Error("ECC public key is required.");
  const recipientKey = ec.keyFromPublic(recipientPublicKeyHex, "hex");
  const ephemeralKey = ec.genKeyPair();
  const ephemeralPubCompressed = Buffer.from(ephemeralKey.getPublic(true, "hex"), "hex");
  const sharedSecret = ephemeralKey.derive(recipientKey.getPublic());
  const sharedSecretBuf = Buffer.from(sharedSecret.toArray("be", 32));
  const aesKey = crypto.createHash("sha256").update(sharedSecretBuf).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const packed = Buffer.concat([ephemeralPubCompressed, iv, authTag, ciphertext]);
  return packed.toString("base64");
}

export function decryptEcc(encryptedBase64: string, recipientPrivateKeyHex: string): string {
  if (!recipientPrivateKeyHex) throw new Error("ECC private key is required.");
  const packed = Buffer.from(encryptedBase64, "base64");
  const ephemeralPub = packed.subarray(0, 33);
  const iv = packed.subarray(33, 45);
  const authTag = packed.subarray(45, 61);
  const ciphertext = packed.subarray(61);
  const recipientKey = ec.keyFromPrivate(recipientPrivateKeyHex, "hex");
  const ephemeralKey = ec.keyFromPublic(ephemeralPub, "hex");
  const sharedSecret = recipientKey.derive(ephemeralKey.getPublic());
  const sharedSecretBuf = Buffer.from(sharedSecret.toArray("be", 32));
  const aesKey = crypto.createHash("sha256").update(sharedSecretBuf).digest();
  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString("utf8");
}

export function hashText(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

export function requireKeyForMethod(method: EncryptionMethod, req: any): void {
  if (method === "AES" && !req.key) {
    throw new Error("AES encryption/decryption requires a symmetric key.");
  }
}
