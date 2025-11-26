import { Component, computed, signal, Inject, PLATFORM_ID, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule, isPlatformBrowser } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { EncryptionApiService } from './services/encryption-api.service';
import {
  EncryptionMethod,
  AsymKeyPairResponse,
  EncryptResponse,
  DecryptResponse,
  AesKeySize,
  HistoryItem
} from './models/encryption.models';

interface AlgorithmInfo {
  id: EncryptionMethod;
  name: string;
  short: string;
  description: string;
  howItWorks: string;
  pros: string[];
  cons: string[];
  uses: string[];
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule, HttpClientModule],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App implements OnInit {
  readonly title = signal('Encryption Playground');

  // State
  readonly selectedMethod = signal<EncryptionMethod>('AES');
  readonly plaintext = signal('');
  readonly encryptedText = signal('');

  // Keys
  readonly aesKey = signal('');
  readonly aesKeySize = signal<AesKeySize>(256);
  readonly rsaPublicKey = signal('');
  readonly rsaPrivateKey = signal('');
  readonly eccPublicKey = signal('');
  readonly eccPrivateKey = signal('');

  // UI State
  readonly isLoading = signal(false);
  readonly errorMessage = signal('');
  readonly infoMessage = signal('');
  readonly lastExecutionTimeMs = signal<number | null>(null);
  readonly lastOperation = signal<'encrypt' | 'decrypt' | null>(null);
  readonly isVisualizing = signal(false);

  // History Drawer State
  readonly showHistoryDrawer = signal(false);
  readonly history = signal<HistoryItem[]>([]);
  readonly selectedHistoryItem = signal<HistoryItem | null>(null);

  // Copy Button Logic
  readonly copyButtonLabel = signal('Copy Result');
  readonly showEncryptCopy = computed(() => !this.isLoading() && this.lastOperation() === 'encrypt' && this.encryptedText().length > 0);
  readonly showDecryptCopy = computed(() => !this.isLoading() && this.lastOperation() === 'decrypt' && this.plaintext().length > 0);

  // Modals
  readonly showAlgorithmModal = signal(false);
  readonly showKeyModal = signal(false);
  readonly activeAlgorithmInfo = signal<AlgorithmInfo | undefined>(undefined);

  readonly aesKeyExample = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...';

  // Visualization Helpers
  readonly plainBits = computed(() => this.toBinary(this.plaintext()));
  readonly cipherBits = computed(() => this.toBinary(this.encryptedText()));

  // Detailed Descriptions
  readonly algorithms = signal<AlgorithmInfo[]>([
    {
      id: 'AES',
      name: 'AES',
      short: 'Advanced Encryption Standard (Symmetric)',
      description: 'AES is the global standard for symmetric encryption. It treats data as blocks and scrambles them using a secret key.',
      howItWorks: 'Data is put into a 4x4 grid. 1. SubBytes (replace bytes) 2. ShiftRows (move rows) 3. MixColumns (math magic) 4. AddRoundKey. This repeats 10-14 times depending on key size.',
      pros: ['Extremely fast', 'Quantum resistant (256-bit)', 'Hardware accelerated'],
      cons: ['Key distribution is hard', 'One key compromises everything'],
      uses: ['WiFi (WPA2)', 'HTTPS', 'File Encryption', 'VPNs'],
    },
    {
      id: 'RSA',
      name: 'RSA',
      short: 'Rivest–Shamir–Adleman (Asymmetric)',
      description: 'RSA relies on the mathematical difficulty of factoring the product of two large prime numbers.',
      howItWorks: 'Uses modular exponentiation. C = M^e mod n (Encrypt), M = C^d mod n (Decrypt). Public key is (e, n), Private is (d, n).',
      pros: ['Secure key exchange', 'Digital signatures', 'No shared secret needed beforehand'],
      cons: ['Slow computation', 'Large key sizes (2048+ bits)', 'Vulnerable to quantum computers'],
      uses: ['SSL/TLS Certificates', 'Email signatures (PGP)', 'Code Signing'],
    },
    {
      id: 'ECC',
      name: 'ECC',
      short: 'Elliptic Curve Cryptography (Asymmetric)',
      description: 'ECC creates keys based on the mathematics of elliptic curves over finite fields.',
      howItWorks: 'Points on a curve y² = x³ + ax + b. Adding a point to itself N times creates a "trapdoor" function that is very hard to reverse (Discrete Logarithm Problem).',
      pros: ['Very efficient', 'Small keys (256-bit ECC ≈ 3072-bit RSA)', 'Low power consumption'],
      cons: ['Complex implementation', 'Quantum vulnerable'],
      uses: ['Bitcoin/Blockchain', 'iMessage', 'Modern SSL (ECDHE)'],
    },
  ]);

  readonly keyExplanation = {
    title: 'What is an encryption key?',
    paragraphs: [
      'An encryption key is essentially a huge number or a string of random bits that determines the output of the encryption algorithm.',
      'Symmetric (AES): Think of a house key. The same key locks (encrypts) and unlocks (decrypts) the door. You must share this key securely with anyone you want to communicate with.',
      'Asymmetric (RSA/ECC): Think of a mailbox. Anyone can drop a letter in the slot (Public Key), but only the person with the unique key can open the box and read the mail (Private Key).',
      'Key Size: Measured in bits (e.g., 128, 256). Larger keys are harder to crack but may be slower to use.'
    ],
  };

  readonly selectedAlgorithm = computed(() => this.algorithms().find((a) => a.id === this.selectedMethod()));

  constructor(
    private readonly api: EncryptionApiService,
    @Inject(PLATFORM_ID) private platformId: Object
  ) {}

  ngOnInit(): void {
    // Исправление ошибки: загружаем историю только в браузере
    if (isPlatformBrowser(this.platformId)) {
      this.loadHistory();
    }
  }

  // --- HISTORY & FILE IO ---
  loadHistory(): void {
    try {
      const stored = localStorage.getItem('enc_app_history');
      if (stored) this.history.set(JSON.parse(stored));
    } catch (e) { console.error(e); }
  }

  addToHistory(op: 'encrypt' | 'decrypt', input: string, output: string): void {
    if (!isPlatformBrowser(this.platformId)) return;
    const item: HistoryItem = {
      id: Date.now().toString(36) + Math.random().toString(36).substr(2),
      timestamp: Date.now(),
      method: this.selectedMethod(),
      operation: op,
      keyUsed: this.getKeyUsedDisplay(),
      input: input.length > 50 ? input.substring(0, 50) + '...' : input,
      output: output.length > 50 ? output.substring(0, 50) + '...' : output
    };
    this.history.update(prev => [item, ...prev].slice(0, 50));
    this.saveHistory();
  }

  getKeyUsedDisplay(): string {
    if (this.selectedMethod() === 'AES') return this.aesKey() ? 'AES Key (Saved)' : 'No Key';
    return this.lastOperation() === 'encrypt' ? 'Public Key' : 'Private Key';
  }

  saveHistory(): void {
    if (isPlatformBrowser(this.platformId)) localStorage.setItem('enc_app_history', JSON.stringify(this.history()));
  }

  clearHistory(): void {
    this.history.set([]);
    if (isPlatformBrowser(this.platformId)) localStorage.removeItem('enc_app_history');
  }

  toggleHistory(): void { this.showHistoryDrawer.update(v => !v); }
  openHistoryDetail(item: HistoryItem): void { this.selectedHistoryItem.set(item); }
  closeHistoryDetail(): void { this.selectedHistoryItem.set(null); }
  formatDate(ts: number): string { return new Date(ts).toLocaleString(); }

  downloadFile(content: string, filename: string): void {
    if (!content || !isPlatformBrowser(this.platformId)) return;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    window.URL.revokeObjectURL(url);
    this.infoMessage.set(`Exported ${filename}`);
  }

  triggerImport(inputId: string): void {
    if (isPlatformBrowser(this.platformId)) document.getElementById(inputId)?.click();
  }

  onFileSelected(event: any, target: string): void {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const res = e.target?.result as string;
      if (target === 'aes') this.aesKey.set(res);
      if (target === 'rsa-pub') this.rsaPublicKey.set(res);
      if (target === 'rsa-priv') this.rsaPrivateKey.set(res);
      if (target === 'ecc-pub') this.eccPublicKey.set(res);
      if (target === 'ecc-priv') this.eccPrivateKey.set(res);
      this.infoMessage.set(`Loaded from ${file.name}`);
    };
    reader.readAsText(file);
    event.target.value = '';
  }

  // --- CORE LOGIC ---
  setMethod(method: EncryptionMethod): void {
    this.selectedMethod.set(method);
    this.resetState();
  }

  setAesSize(size: AesKeySize): void {
    this.aesKeySize.set(size);
    this.aesKey.set('');
    this.infoMessage.set(`Switched to AES-${size}. Generate a new key.`);
  }

  resetState() {
    this.errorMessage.set('');
    this.infoMessage.set('');
    this.isVisualizing.set(false);
    this.lastOperation.set(null);
    this.copyButtonLabel.set('Copy Result');
  }

  toBinary(input: string): string {
    if (!input) return '';
    return input.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join(' ').substring(0, 300) + (input.length > 35 ? '...' : '');
  }

  openAlgorithmModal(alg: AlgorithmInfo): void { this.activeAlgorithmInfo.set(alg); this.showAlgorithmModal.set(true); }
  closeAlgorithmModal(): void { this.showAlgorithmModal.set(false); }
  openKeyModal(): void { this.showKeyModal.set(true); }
  closeKeyModal(): void { this.showKeyModal.set(false); }

  onEncrypt(): void {
    this.resetState();
    this.isVisualizing.set(true);
    if (!this.plaintext().trim()) { this.errorMessage.set('Please enter text.'); this.isVisualizing.set(false); return; }

    const body: any = { method: this.selectedMethod(), text: this.plaintext() };
    if (this.selectedMethod() === 'AES') {
      if (!this.aesKey()) { this.errorMessage.set('AES key required'); this.isVisualizing.set(false); return; }
      body.key = this.aesKey();
    } else if (this.selectedMethod() === 'RSA') {
      if (!this.rsaPublicKey()) { this.errorMessage.set('Public key required'); this.isVisualizing.set(false); return; }
      body.publicKey = this.rsaPublicKey();
    } else {
      if (!this.eccPublicKey()) { this.errorMessage.set('Public key required'); this.isVisualizing.set(false); return; }
      body.publicKey = this.eccPublicKey();
    }

    this.isLoading.set(true);
    this.api.encrypt(body).subscribe({
      next: (res: EncryptResponse) => {
        setTimeout(() => {
          this.encryptedText.set(res.encryptedText);
          this.lastExecutionTimeMs.set(res.executionTimeMs);
          this.lastOperation.set('encrypt');
          this.infoMessage.set(`Encrypted in ${res.executionTimeMs.toFixed(2)}ms`);
          this.isLoading.set(false);
          this.addToHistory('encrypt', this.plaintext(), res.encryptedText);
        }, 800);
      },
      error: (err) => { this.errorMessage.set(err.error?.error || 'Error'); this.isLoading.set(false); this.isVisualizing.set(false); }
    });
  }

  onDecrypt(): void {
    this.resetState();
    this.isVisualizing.set(true);
    if (!this.encryptedText().trim()) { this.errorMessage.set('No encrypted text.'); this.isVisualizing.set(false); return; }

    const body: any = { method: this.selectedMethod(), encryptedText: this.encryptedText() };
    if (this.selectedMethod() === 'AES') {
      if (!this.aesKey()) { this.errorMessage.set('AES key required'); this.isVisualizing.set(false); return; }
      body.key = this.aesKey();
    } else if (this.selectedMethod() === 'RSA') {
      if (!this.rsaPrivateKey()) { this.errorMessage.set('Private key required'); this.isVisualizing.set(false); return; }
      body.privateKey = this.rsaPrivateKey();
    } else {
      if (!this.eccPrivateKey()) { this.errorMessage.set('Private key required'); this.isVisualizing.set(false); return; }
      body.privateKey = this.eccPrivateKey();
    }

    this.isLoading.set(true);
    this.api.decrypt(body).subscribe({
      next: (res: DecryptResponse) => {
        setTimeout(() => {
          this.plaintext.set(res.decryptedText);
          this.lastExecutionTimeMs.set(res.executionTimeMs);
          this.lastOperation.set('decrypt');
          this.infoMessage.set(`Decrypted in ${res.executionTimeMs.toFixed(2)}ms`);
          this.isLoading.set(false);
          this.addToHistory('decrypt', this.encryptedText(), res.decryptedText);
        }, 800);
      },
      error: (err) => { this.errorMessage.set(err.error?.error || 'Error'); this.isLoading.set(false); this.isVisualizing.set(false); }
    });
  }

  copyResult(): void {
    const txt = this.lastOperation() === 'encrypt' ? this.encryptedText() : this.plaintext();
    if (txt && isPlatformBrowser(this.platformId)) {
      navigator.clipboard.writeText(txt).then(() => {
        this.copyButtonLabel.set('Copied!');
        setTimeout(() => this.copyButtonLabel.set('Copy Result'), 2000);
      });
    }
  }

  onGenerateAesKey() { this.api.generateAesKey(this.aesKeySize()).subscribe(res => this.aesKey.set(res.key)); }
  onGenerateRsaKeys() { this.isLoading.set(true); this.api.generateRsaKeys().subscribe(res => { this.rsaPublicKey.set(res.publicKey); this.rsaPrivateKey.set(res.privateKey); this.isLoading.set(false); }); }
  onGenerateEccKeys() { this.isLoading.set(true); this.api.generateEccKeys().subscribe(res => { this.eccPublicKey.set(res.publicKey); this.eccPrivateKey.set(res.privateKey); this.isLoading.set(false); }); }
}
