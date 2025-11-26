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

export interface FileEncryptRequest {
  method: EncryptionMethod;
  dataBase64: string;
  key?: string;
  publicKey?: string;
  fileName?: string;
  mimeType?: string;
}

export interface FileEncryptResponse {
  encryptedData: string;
  method: EncryptionMethod;
  executionTimeMs: number;
  fileName?: string;
  mimeType?: string;
}

export interface FileDecryptRequest {
  method: EncryptionMethod;
  encryptedDataBase64: string;
  key?: string;
  privateKey?: string;
}

export interface FileDecryptResponse {
  dataBase64: string;
  method: EncryptionMethod;
  executionTimeMs: number;
}

export interface OperationLog {
  id: number;
  method: EncryptionMethod;
  operation_type: 'encrypt' | 'decrypt';
  text_hash: string;
  execution_time_ms: number;
  created_at: string;
}
