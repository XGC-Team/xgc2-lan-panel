/** IPv4 helpers for the LAN Panel static-address form. */

export function parsePrefix(mask: string): number | null {
  const text = mask.trim().replace(/^\//, '');
  if (text === '') return null;
  if (/^\d{1,2}$/.test(text)) {
    const prefix = Number(text);
    return prefix >= 1 && prefix <= 32 ? prefix : null;
  }
  const octets = text.split('.');
  if (octets.length !== 4) return null;
  const nums = octets.map((part) => Number(part));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  let bits = 0;
  let seenZero = false;
  for (const octet of nums) {
    for (let i = 7; i >= 0; i -= 1) {
      const bit = (octet >> i) & 1;
      if (bit === 0) {
        seenZero = true;
      } else if (seenZero) {
        return null;
      } else {
        bits += 1;
      }
    }
  }
  return bits === 0 ? null : bits;
}

export function parseIPv4(ip: string): number | null {
  const text = ip.trim();
  const octets = text.split('.');
  if (octets.length !== 4) return null;
  const nums = octets.map((part) => Number(part));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
}

export function formatIPv4(value: number): string {
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  ].join('.');
}

export function splitHostMask(input: string): { ip: string; mask: string } {
  const text = input.trim();
  const slash = text.indexOf('/');
  if (slash < 0) return { ip: text, mask: '' };
  return { ip: text.slice(0, slash).trim(), mask: text.slice(slash + 1).trim() };
}

/** Field convention: gateway and DNS are the first usable host (network + 1). */
export function networkGateway(ip: string, mask: string): string | null {
  const addr = parseIPv4(ip);
  const prefix = parsePrefix(mask);
  if (addr == null || prefix == null || prefix > 30) return null;
  const hostMask = prefix === 32 ? 0 : (0xffffffff >>> prefix);
  const network = (addr & (~hostMask >>> 0)) >>> 0;
  return formatIPv4((network + 1) >>> 0);
}

export function composeCIDR(ip: string, mask: string): string | null {
  const host = parseIPv4(ip);
  const prefix = parsePrefix(mask);
  if (host == null || prefix == null) return null;
  return `${formatIPv4(host)}/${prefix}`;
}
