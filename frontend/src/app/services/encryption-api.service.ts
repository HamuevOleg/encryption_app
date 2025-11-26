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
}
