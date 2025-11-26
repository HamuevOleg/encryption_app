export type EncryptionMethod = "AES" | "RSA" | "ECC";

export interface EncryptRequestDto {
  method: EncryptionMethod;
  text: string;
  key?: string;
  publicKey?: string;
}

export interface EncryptResponseDto {
  encryptedText: string;
  method: EncryptionMethod;
  executionTimeMs: number;
}

export interface DecryptRequestDto {
  method: EncryptionMethod;
  encryptedText: string;
  key?: string;
  privateKey?: string;
}

export interface DecryptResponseDto {
  decryptedText: string;
  method: EncryptionMethod;
  executionTimeMs: number;
}

export interface AesKeyResponseDto {
  key: string;
}

export interface AsymKeyPairResponseDto {
  publicKey: string;
  privateKey: string;
}

export interface FileEncryptRequestDto {
  method: EncryptionMethod;
  dataBase64: string;
  key?: string;
  publicKey?: string;
  fileName?: string;
  mimeType?: string;
}

export interface FileEncryptResponseDto {
  encryptedData: string;
  method: EncryptionMethod;
  executionTimeMs: number;
  fileName?: string;
  mimeType?: string;
}

export interface FileDecryptRequestDto {
  method: EncryptionMethod;
  encryptedDataBase64: string;
  key?: string;
  privateKey?: string;
}

export interface FileDecryptResponseDto {
  dataBase64: string;
  method: EncryptionMethod;
  executionTimeMs: number;
}
