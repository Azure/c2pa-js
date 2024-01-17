/**
 * Copyright 2021 Adobe
 * All Rights Reserved.
 *
 * NOTICE: Adobe permits you to use, modify, and distribute this file in
 * accordance with the terms of the Adobe license agreement accompanying
 * it.
 */

import { setupWorker } from './src/lib/pool/worker';

import {
  default as initDetector,
  scan_array_buffer,
} from '@contentauth/detector';
import {
  ManifestStore,
  getManifestStoreFromArrayBuffer,
  getManifestStoreFromManifestAndAsset,
  signAssetBuffer,
  default as initToolkit,
} from '@contentauth/toolkit';
import {
  SigningData,
  WebCryptoSigner,
  createSigningInfo,
} from './src/lib/signer';

export interface IScanResult {
  found: boolean;
  offset?: number;
}

const worker = {
  async compileWasm(buffer: ArrayBuffer): Promise<WebAssembly.Module> {
    return WebAssembly.compile(buffer);
  },
  async getReport(
    wasm: WebAssembly.Module,
    buffer: ArrayBuffer,
    type: string,
  ): Promise<ManifestStore> {
    await initToolkit(wasm);
    return getManifestStoreFromArrayBuffer(buffer, type);
  },
  async getReportFromAssetAndManifestBuffer(
    wasm: WebAssembly.Module,
    manifestBuffer: ArrayBuffer,
    asset: Blob,
  ) {
    await initToolkit(wasm);
    const assetBuffer = await asset.arrayBuffer();
    return getManifestStoreFromManifestAndAsset(
      manifestBuffer,
      assetBuffer,
      asset.type,
    );
  },
  async scanInput(
    wasm: WebAssembly.Module,
    buffer: ArrayBuffer,
  ): Promise<IScanResult> {
    await initDetector(wasm);
    try {
      const offset = await scan_array_buffer(buffer);
      return { found: true, offset };
    } catch (err) {
      return { found: false };
    }
  },

  async sign(
    wasm: WebAssembly.Module,
    buffer: ArrayBuffer,
    type: string,
    data: SigningData,
  ): Promise<ArrayBuffer> {
    if (!data.key) {
      throw new Error('Crypto key not provided!');
    }
    await initToolkit(wasm);
    const signer = new WebCryptoSigner(data.alg, data.key);
    const info = createSigningInfo(data, signer);
    return signAssetBuffer(info, buffer, type);
  },
};

export type Worker = typeof worker;

setupWorker(worker);
