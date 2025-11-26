import { Component, computed, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { EncryptionApiService } from './services/encryption-api.service';
import {
  EncryptionMethod,
  AsymKeyPairResponse,
  EncryptResponse,
  DecryptResponse,
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
export class App {
  readonly title = signal('Encryption Playground');

  // State
  readonly selectedMethod = signal<EncryptionMethod>('AES');
  readonly plaintext = signal('');
  readonly encryptedText = signal('');
  readonly aesKey = signal('');
  readonly rsaPublicKey = signal('');
  readonly rsaPrivateKey = signal('');
  readonly eccPublicKey = signal('');
  readonly eccPrivateKey = signal('');

  readonly isLoading = signal(false);
  readonly errorMessage = signal('');
  readonly infoMessage = signal('');
  readonly lastExecutionTimeMs = signal<number | null>(null);
  readonly lastOperation = signal<'encrypt' | 'decrypt' | null>(null);

  readonly showAlgorithmModal = signal(false);
  readonly showKeyModal = signal(false);
  readonly activeAlgorithmInfo = signal<AlgorithmInfo | undefined>(undefined);

  // Example key for display
  readonly aesKeyExample = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...';

  readonly algorithms = signal<AlgorithmInfo[]>([
    {
      id: 'AES',
      name: 'AES',
      short: 'Advanced Encryption Standard (symmetric)',
      description:
        'AES is a fast, modern symmetric cipher used to protect data at rest and in transit.',
      howItWorks:
        'The same secret key is used to encrypt and decrypt. Data is scrambled with mathematical operations in several rounds.',
      pros: [
        'Very fast',
        'Widely standardized and trusted',
        'Great for large amounts of data',
      ],
      cons: ['Key must be kept secret and shared safely', 'Not ideal for key exchange'],
      uses: ['Disk encryption', 'TLS (with symmetric ciphers)', 'VPNs'],
    },
    {
      id: 'RSA',
      name: 'RSA',
      short: 'Rivest–Shamir–Adleman (asymmetric)',
      description:
        'RSA is a classic public‑key algorithm mainly used for key exchange and digital signatures.',
      howItWorks:
        'You have a key pair: a public key (shareable) and a private key (secret). Data encrypted with the public key can only be decrypted with the matching private key.',
      pros: [
        'No need to share private keys',
        'Good for exchanging symmetric keys',
        'Well‑understood and widely used',
      ],
      cons: ['Slower than AES', 'Key sizes are large', 'Being replaced by ECC in some areas'],
      uses: ['TLS handshakes', 'Secure email (PGP)', 'Code signing'],
    },
    {
      id: 'ECC',
      name: 'ECC',
      short: 'Elliptic Curve Cryptography (asymmetric)',
      description:
        'ECC uses elliptic curves to provide strong security with smaller keys than RSA.',
      howItWorks:
        "You also have a public/private key pair, but the math is based on elliptic curves. It's usually combined with AES in a scheme similar to ECIES.",
      pros: [
        'Smaller keys for similar security',
        'Efficient for mobile and low‑power devices',
        'Modern replacement for large RSA keys',
      ],
      cons: [
        'More complex math and implementations',
        'Interoperability can be trickier',
        'Still evolving in standards compared to RSA',
      ],
      uses: ['Modern TLS (ECDHE)', 'Cryptocurrency wallets', 'Secure messaging protocols'],
    },
  ]);

  readonly keyExplanation = {
    title: 'What is an encryption key?',
    paragraphs: [
      'An encryption key is a piece of information (usually random bytes) that controls how data is scrambled and unscrambled.',
      'With symmetric encryption (like AES), the same key is used to encrypt and decrypt. Everyone who needs to read the data must share this key securely.',
      'With asymmetric encryption (like RSA and ECC), you have a key pair: a public key and a private key.',
      'The public key can be shared with anyone and is used to encrypt data or verify signatures. The private key must be kept secret and is used to decrypt data or create signatures.',
      'In this app, AES uses one secret key. RSA and ECC use a public key for encryption and a private key for decryption.',
    ],
  };

  readonly selectedAlgorithm = computed(() =>
    this.algorithms().find((a) => a.id === this.selectedMethod())
  );

  constructor(private readonly api: EncryptionApiService) {}

  setMethod(method: EncryptionMethod): void {
    this.selectedMethod.set(method);
    this.errorMessage.set('');
    this.infoMessage.set('');
  }

  openAlgorithmModal(alg: AlgorithmInfo): void {
    this.activeAlgorithmInfo.set(alg);
    this.showAlgorithmModal.set(true);
  }

  closeAlgorithmModal(): void {
    this.showAlgorithmModal.set(false);
  }

  openKeyModal(): void {
    this.showKeyModal.set(true);
  }

  closeKeyModal(): void {
    this.showKeyModal.set(false);
  }

  onEncrypt(): void {
    this.errorMessage.set('');
    this.infoMessage.set('');
    this.lastExecutionTimeMs.set(null);
    this.lastOperation.set(null);

    if (!this.plaintext().trim()) {
      this.errorMessage.set('Please enter some text to encrypt.');
      return;
    }

    const method = this.selectedMethod();

    const body: any = {
      method,
      text: this.plaintext(),
    };

    if (method === 'AES') {
      if (!this.aesKey()) {
        this.errorMessage.set('AES requires a key. Generate or paste one.');
        return;
      }
      body.key = this.aesKey();
    } else if (method === 'RSA') {
      if (!this.rsaPublicKey()) {
        this.errorMessage.set('RSA encryption requires a public key.');
        return;
      }
      body.publicKey = this.rsaPublicKey();
    } else if (method === 'ECC') {
      if (!this.eccPublicKey()) {
        this.errorMessage.set('ECC encryption requires a public key.');
        return;
      }
      body.publicKey = this.eccPublicKey();
    }

    this.isLoading.set(true);
    this.api.encrypt(body).subscribe({
      next: (res: EncryptResponse) => {
        this.encryptedText.set(res.encryptedText);
        this.lastExecutionTimeMs.set(res.executionTimeMs);
        this.lastOperation.set('encrypt');
        this.infoMessage.set(
          `Server encrypted the text using ${res.method} in ${res.executionTimeMs.toFixed(1)} ms.`
        );
        this.isLoading.set(false);
      },
      error: (err) => {
        this.errorMessage.set(err.error?.error || 'Encryption failed.');
        this.isLoading.set(false);
      },
    });
  }

  onDecrypt(): void {
    this.errorMessage.set('');
    this.infoMessage.set('');
    this.lastExecutionTimeMs.set(null);
    this.lastOperation.set(null);

    if (!this.encryptedText().trim()) {
      this.errorMessage.set('Please provide encrypted text to decrypt.');
      return;
    }

    const method = this.selectedMethod();

    const body: any = {
      method,
      encryptedText: this.encryptedText(),
    };

    if (method === 'AES') {
      if (!this.aesKey()) {
        this.errorMessage.set('AES decryption requires a key.');
        return;
      }
      body.key = this.aesKey();
    } else if (method === 'RSA') {
      if (!this.rsaPrivateKey()) {
        this.errorMessage.set('RSA decryption requires a private key.');
        return;
      }
      body.privateKey = this.rsaPrivateKey();
    } else if (method === 'ECC') {
      if (!this.eccPrivateKey()) {
        this.errorMessage.set('ECC decryption requires a private key.');
        return;
      }
      body.privateKey = this.eccPrivateKey();
    }

    this.isLoading.set(true);
    this.api.decrypt(body).subscribe({
      next: (res: DecryptResponse) => {
        this.plaintext.set(res.decryptedText);
        this.lastExecutionTimeMs.set(res.executionTimeMs);
        this.lastOperation.set('decrypt');
        this.infoMessage.set(
          `Server decrypted the text using ${res.method} in ${res.executionTimeMs.toFixed(1)} ms.`
        );
        this.isLoading.set(false);
      },
      error: (err) => {
        this.errorMessage.set(err.error?.error || 'Decryption failed.');
        this.isLoading.set(false);
      },
    });
  }

  onGenerateAesKey(): void {
    this.errorMessage.set('');
    this.isLoading.set(true);
    this.api.generateAesKey().subscribe({
      next: (res) => {
        this.aesKey.set(res.key);
        this.infoMessage.set('New AES key generated successfully!');
        this.isLoading.set(false);
      },
      error: () => {
        this.errorMessage.set('Failed to generate AES key.');
        this.isLoading.set(false);
      },
    });
  }

  onGenerateRsaKeys(): void {
    this.errorMessage.set('');
    this.isLoading.set(true);
    this.api.generateRsaKeys().subscribe({
      next: (res: AsymKeyPairResponse) => {
        this.rsaPublicKey.set(res.publicKey);
        this.rsaPrivateKey.set(res.privateKey);
        this.infoMessage.set('New RSA key pair generated successfully!');
        this.isLoading.set(false);
      },
      error: () => {
        this.errorMessage.set('Failed to generate RSA key pair.');
        this.isLoading.set(false);
      },
    });
  }

  onGenerateEccKeys(): void {
    this.errorMessage.set('');
    this.isLoading.set(true);
    this.api.generateEccKeys().subscribe({
      next: (res: AsymKeyPairResponse) => {
        this.eccPublicKey.set(res.publicKey);
        this.eccPrivateKey.set(res.privateKey);
        this.infoMessage.set('New ECC key pair generated successfully!');
        this.isLoading.set(false);
      },
      error: () => {
        this.errorMessage.set('Failed to generate ECC key pair.');
        this.isLoading.set(false);
      },
    });
  }
}
