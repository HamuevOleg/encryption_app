export type EncryptionMethod = 'AES' | 'RSA' | 'ECC';

export interface EncryptRequest {
  method: EncryptionMethod;
  text: string;
  key?: string;
  publicKey?: string;
}

export interface EncryptResponse {
  encryptedText: string;
  method: EncryptionMethod;
  executionTimeMs: number;
}

export interface DecryptRequest {
  method: EncryptionMethod;
  encryptedText: string;
  key?: string;
  privateKey?: string;
}

export interface DecryptResponse {
  decryptedText: string;
  method: EncryptionMethod;
  executionTimeMs: number;
}

export interface AesKeyResponse {
  key: string;
}

export interface AsymKeyPairResponse {
  publicKey: string;
  privateKey: string;
}
