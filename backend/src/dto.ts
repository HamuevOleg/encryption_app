export type EncryptionMethod = "AES" | "RSA" | "ECC";

export interface EncryptRequestDto {
  method: EncryptionMethod;
  text: string;
  key?: string;
  publicKey?: string;
}

export interface EncryptResponseDto {
  encryptedText: string;
}

export interface DecryptRequestDto {
  method: EncryptionMethod;
  encryptedText: string;
  key?: string;
  privateKey?: string;
}

export interface DecryptResponseDto {
  decryptedText: string;
}

export interface AesKeyResponseDto {
  key: string;
}

export interface AsymKeyPairResponseDto {
  publicKey: string;
  privateKey: string;
}
