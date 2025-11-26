import { inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  EncryptRequest,
  EncryptResponse,
  DecryptRequest,
  DecryptResponse,
  AesKeyResponse,
  AsymKeyPairResponse,
  FileEncryptRequest,
  FileEncryptResponse,
  FileDecryptRequest,
  FileDecryptResponse,
  OperationLog,
} from '../models/encryption.models';
import { environment } from '../../environments/environment';

@Injectable({ providedIn: 'root' })
export class EncryptionApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = environment.apiUrl;

  encrypt(body: EncryptRequest): Observable<EncryptResponse> {
    return this.http.post<EncryptResponse>(`${this.baseUrl}/encrypt`, body);
  }

  decrypt(body: DecryptRequest): Observable<DecryptResponse> {
    return this.http.post<DecryptResponse>(`${this.baseUrl}/decrypt`, body);
  }

  generateAesKey(): Observable<AesKeyResponse> {
    return this.http.post<AesKeyResponse>(`${this.baseUrl}/generate-key/aes`, {});
  }

  generateRsaKeys(): Observable<AsymKeyPairResponse> {
    return this.http.post<AsymKeyPairResponse>(`${this.baseUrl}/generate-key/rsa`, {});
  }

  generateEccKeys(): Observable<AsymKeyPairResponse> {
    return this.http.post<AsymKeyPairResponse>(`${this.baseUrl}/generate-key/ecc`, {});
  }

  encryptFile(body: FileEncryptRequest): Observable<FileEncryptResponse> {
    return this.http.post<FileEncryptResponse>(`${this.baseUrl}/encrypt-file`, body);
  }

  decryptFile(body: FileDecryptRequest): Observable<FileDecryptResponse> {
    return this.http.post<FileDecryptResponse>(`${this.baseUrl}/decrypt-file`, body);
  }

  getRecentOperations(limit = 10): Observable<OperationLog[]> {
    return this.http.get<OperationLog[]>(`${this.baseUrl}/operations`);
  }
}
