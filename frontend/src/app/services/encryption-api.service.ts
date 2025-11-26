import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import {
  AsymKeyPairResponse,
  DecryptRequest,
  DecryptResponse,
  EncryptRequest,
  EncryptResponse,
  GenerateKeyResponse,
  AesKeySize
} from '../models/encryption.models';

@Injectable({
  providedIn: 'root',
})
export class EncryptionApiService {
  private readonly apiUrl = environment.apiUrl;

  constructor(private readonly http: HttpClient) {}

  generateAesKey(size: AesKeySize = 256): Observable<GenerateKeyResponse> {
    return this.http.get<GenerateKeyResponse>(`${this.apiUrl}/keys/aes`, {
      params: { size: size.toString() }
    });
  }

  generateRsaKeys(): Observable<AsymKeyPairResponse> {
    return this.http.post<AsymKeyPairResponse>(`${this.apiUrl}/keys/rsa`, {});
  }

  generateEccKeys(): Observable<AsymKeyPairResponse> {
    return this.http.post<AsymKeyPairResponse>(`${this.apiUrl}/keys/ecc`, {});
  }

  encrypt(data: EncryptRequest): Observable<EncryptResponse> {
    return this.http.post<EncryptResponse>(`${this.apiUrl}/encrypt`, data);
  }

  decrypt(data: DecryptRequest): Observable<DecryptResponse> {
    return this.http.post<DecryptResponse>(`${this.apiUrl}/decrypt`, data);
  }
}
