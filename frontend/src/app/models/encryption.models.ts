export type EncryptionMethod = 'AES' | 'RSA' | 'ECC';
export type AesKeySize = 128 | 192 | 256;

export interface GenerateKeyResponse {
  key: string;
}

export interface AsymKeyPairResponse {
  publicKey: string;
  privateKey: string;
}

export interface EncryptRequest {
  method: EncryptionMethod;
  text: string;
  key?: string;
  publicKey?: string;
}

export interface DecryptRequest {
  method: EncryptionMethod;
  encryptedText: string;
  key?: string;
  privateKey?: string;
}

export interface EncryptResponse {
  method: EncryptionMethod;
  encryptedText: string;
  executionTimeMs: number;
}

export interface DecryptResponse {
  method: EncryptionMethod;
  decryptedText: string;
  executionTimeMs: number;
}

export interface HistoryItem {
  id: string;
  timestamp: number;
  method: EncryptionMethod;
  operation: 'encrypt' | 'decrypt';
  keyUsed: string;
  input: string;
  output: string;
}
