export function base64ToBytes(value?: string): Uint8Array {
  if (!value) return new Uint8Array();
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return new Uint8Array();
  }
}

export function hexDump(data: Uint8Array, limit = 4096): string {
  const bytes = data.length > limit ? data.subarray(0, limit) : data;
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.subarray(offset, offset + 16);
    const hex: string[] = [];
    let ascii = '';
    for (let i = 0; i < 16; i += 1) {
      if (i < chunk.length) {
        hex.push(chunk[i].toString(16).padStart(2, '0').toUpperCase());
        const code = chunk[i];
        ascii += code >= 32 && code < 127 ? String.fromCharCode(code) : '.';
      } else {
        hex.push('  ');
        ascii += ' ';
      }
    }
    lines.push(`${offset.toString(16).padStart(4, '0').toUpperCase()}  ${hex.slice(0, 8).join(' ')}  ${hex.slice(8).join(' ')}  |${ascii}|`);
  }
  return lines.join('\n');
}
