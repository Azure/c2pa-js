import {
  C2paAuthoring,
  createC2paAuthoring,
  SigningData,
  WebCryptoSigner,
} from 'c2pa';
import wasmSrc from 'c2pa/dist/assets/wasm/toolkit_bg.wasm?url';
import workerSrc from 'c2pa/dist/c2pa.worker.js?url';

const keyPem =
  'https://raw.githubusercontent.com/contentauth/c2pa-rs/main/sdk/tests/fixtures/certs/es256.pem';
const certificatesPem =
  'https://raw.githubusercontent.com/contentauth/c2pa-rs/main/sdk/tests/fixtures/certs/es256.pub';

let certificates: ArrayBuffer[] | undefined = undefined;
let directory: FileSystemDirectoryHandle;
let key: CryptoKey | undefined = undefined;

function base64Decode(value: string): ArrayBuffer {
  const data = atob(value);
  const bytes = new Uint8Array(data.length);
  for (let i = 0; i < data.length; ++i) {
    bytes[i] = data.charCodeAt(i);
  }

  return bytes.buffer;
}

function getDerFromPem(value: string, tag: string): ArrayBuffer {
  const prefix = `-----BEGIN ${tag}-----\n`;
  const suffix = `\n-----END ${tag}-----`;
  const start = value.indexOf(prefix) + prefix.length;
  const end = value.indexOf(suffix);
  const base64 = value
    .substring(start, end == -1 ? undefined : end)
    .replaceAll('\n', '');
  return base64Decode(base64);
}

async function createThumbnail(
  blob: Blob,
  type = 'image/png',
  width = 256,
  height = 144,
) {
  const bitmap = await createImageBitmap(blob, {
    resizeWidth: width,
    resizeHeight: height,
  });
  const canvas = new OffscreenCanvas(width, height);
  const context = canvas.getContext('bitmaprenderer')!;
  context.transferFromImageBitmap(bitmap);
  const image = await canvas.convertToBlob({ type });
  return await image.arrayBuffer();
}

const save = async (
  dir: FileSystemDirectoryHandle,
  name: string,
  buffer: ArrayBuffer,
): Promise<void> => {
  console.log('saving buffer', buffer.byteLength);
  const file = await dir.getFileHandle(name, { create: true });
  const stream = await file.createWritable();
  await stream.write(buffer);
  stream.close();
  console.log('file saved');
};

async function getCertificates() {
  let response = await fetch(certificatesPem);
  let text = await response.text();
  const certs = text.split('-----END CERTIFICATE-----\n');
  certificates = certs
    .filter((c) => c.length !== 0)
    .map((c) => getDerFromPem(c, 'CERTIFICATE'));
  document.getElementById(
    'certificates',
  )!.innerText = `Count: ${certificates.length}`;

  response = await fetch(keyPem);
  text = await response.text();
  const buffer = getDerFromPem(text, 'PRIVATE KEY');
  const alg = {
    name: 'ECDSA',
    namedCurve: 'P-256',
  };
  key = await crypto.subtle.importKey('pkcs8', buffer, alg, true, ['sign']);
}

type Status =
  | 'Not Started'
  | 'Downloading'
  | 'Generating Claim'
  | 'Signing Claim'
  | 'Timestamping'
  | 'Completed'
  | 'Failed';

function setStatus(
  tr: HTMLTableRowElement,
  status: Status,
  time?: number,
  thumbnail?: ArrayBuffer,
) {
  const cols = tr.getElementsByTagName('td');
  cols.item(1)!.innerText = status;
  cols.item(2)!.innerText = `${time}`;
  if (thumbnail) {
    const url = URL.createObjectURL(
      new Blob([thumbnail], { type: 'image/png' }),
    );
    tr.getElementsByTagName('img').item(0)!.src = url;
  }
}

const pickDirectory = async () => {
  directory = await window.showDirectoryPicker({
    mode: 'readwrite',
    startIn: 'pictures',
  });
  console.log(directory);
  document.getElementById('output')!.innerText = `${directory.name}`;
};

function addFile(table: HTMLElement, file: File): HTMLTableRowElement {
  const row = document.createElement('tr') as HTMLTableRowElement;
  row.innerHTML = `<td>${file.name}</td><td></td><td></td><td><image></img>'</td>`;
  table.appendChild(row);
  setStatus(row, 'Not Started');
  return row;
}

async function signFile(
  c2pa: C2paAuthoring,
  file: File,
  row: HTMLTableRowElement,
) {
  console.log('Signing', file);

  const thumbnail = await createThumbnail(file, 'image/png');
  setStatus(row, 'Downloading', undefined, thumbnail);
  const callback = new WebCryptoSigner('es256', key!);

  const assertions: Map<string, string> = new Map([
    [
      'c2pa.actions',
      `{
      "actions": [
        {
          "action": "c2pa.created"
        }
      ]
      }`,
    ],
    [
      'stds.exif',
      `{
        "@context" : {
          "exif": "http://ns.adobe.com/exif/1.0/"
        },
        "exif:GPSVersionID": "2.2.0.0",
        "exif:GPSLatitude": "39,21.102N",
        "exif:GPSLongitude": "74,26.5737W",
        "exif:GPSAltitudeRef": 0,
        "exif:GPSAltitude": "100963/29890",
        "exif:GPSTimeStamp": "2019-09-22T18:22:57Z"
      }`,
    ],
    [
      'stds.schema-org.CreativeWork',
      `{
      "@context": "https://schema.org",
      "@type": "CreativeWork",
      "author": [
        {
          "@type": "Person",
          "name": "Prakash Duggaraju"
        }
      ]
    }`,
    ],
  ]);

  const data: SigningData = {
    key: key!,
    certificates: certificates!,
    alg: 'es256',
    thumbnail: thumbnail,
    thumbnail_format: 'image/png',
    assertions,
  };

  try {
    performance.mark('start');
    const result = await c2pa.sign(file, data, callback);
    setStatus(row, 'Downloading');
    await save(directory, file.name, result.asset!);

    performance.mark('end');
    const measure = performance.measure('signing time', 'start', 'end');
    console.log('Time for signing', file.name, measure.duration, 'ms');
    console.log('signing succeeded');
    setStatus(row, 'Completed', measure.duration);
  } catch (e) {
    console.error('Signing failed', e);
    setStatus(row, 'Failed');
  }
}

const signFiles = async (c2pa: C2paAuthoring, files: FileList) => {
  const table = document.getElementById('table')!;
  table.innerHTML = '';
  const rows = Array.from(files).map((file) => addFile(table, file));
  for (const i in rows) {
    await signFile(c2pa, files[i], rows[i]);
  }
};

const initialize = async () => {
  const c2pa = await createC2paAuthoring({
    wasmSrc,
    workerSrc,
  });
  document.getElementById('button')?.addEventListener('click', pickDirectory);
  document.getElementById('input')?.addEventListener('change', async (e) => {
    const target = e.target! as HTMLInputElement;
    await signFiles(c2pa, target.files!);
  });
  document.getElementById('certs')?.addEventListener('click', getCertificates);
};

document.addEventListener('DOMContentLoaded', initialize);
