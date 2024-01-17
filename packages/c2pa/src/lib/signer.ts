/**
 * Copyright 2024 Adobe
 * All Rights Reserved.
 *
 * NOTICE: Adobe permits you to use, modify, and distribute this file in
 * accordance with the terms of the Adobe license agreement accompanying
 * it.
 */

import { Algorithm, AssertionLabel, SigningInfo } from '@contentauth/toolkit';

export interface SigningData {
  alg: Algorithm;
  key: CryptoKey | undefined;
  certificates: ArrayBuffer[];
  thumbnail: ArrayBuffer | undefined;
  thumbnail_format: string | undefined;
  assertions: Map<AssertionLabel, string> | undefined;
}

export interface SigningCallback {
  digest: (buffer: ArrayBuffer) => Promise<ArrayBuffer>;
  sign: (buffer: ArrayBuffer) => Promise<ArrayBuffer>;
  timestamp?: (buffer: ArrayBuffer) => Promise<ArrayBuffer>;
  random: (size: number) => Promise<ArrayBuffer>;
}

export class WebCryptoSigner implements SigningCallback {
  constructor(private alg: Algorithm, private key: CryptoKey) {}

  getDigestAlg() {
    switch (this.alg) {
      case 'es256':
      case 'ps256':
        return 'SHA-256';
        break;
      case 'es384':
      case 'ps384':
        return 'SHA-384';
        break;
      case 'ps512':
      case 'es512':
        return 'SHA-512';
        break;
      default:
        throw new Error(`No mapping for ${this.alg}`);
    }
  }

  getAlg() {
    switch (this.alg) {
      case 'es256':
        return {
          name: 'ECDSA',
          hash: this.getDigestAlg(),
        };
        break;
      default:
        throw new Error('not supported!');
    }
  }

  async digest(data: ArrayBuffer): Promise<ArrayBuffer> {
    return crypto.subtle.digest(this.getDigestAlg(), data);
  }

  async sign(data: ArrayBuffer): Promise<ArrayBuffer> {
    const alg = this.getAlg();
    return crypto.subtle.sign(alg, this.key, data);
  }

  random(size: number) {
    return Promise.resolve(crypto.getRandomValues(new Uint8Array(size)));
  }
}

export function createSigningInfo(
  data: SigningData,
  callback: SigningCallback,
): SigningInfo {
  return {
    certificates: data.certificates,
    alg: data.alg,
    thumbnail: data.thumbnail ? new Uint8Array(data.thumbnail) : undefined,
    thumbnail_format: data.thumbnail_format,
    assertions: data.assertions,
    sign: callback.sign.bind(callback),
    digest: callback.digest.bind(callback),
    random: callback.random.bind(callback),
    timestamp: callback.timestamp?.bind(callback),
  };
}
