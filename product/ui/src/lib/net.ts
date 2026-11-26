// Is an address inside the home network? Mirrors flagman-core's net.rs:
// private IPv4 ranges, link-local and loopback, and their IPv6 equivalents.

export function isLocal(ip: string): boolean {
  if (ip.includes(':')) {
    const lower = ip.toLowerCase();
    if (lower === '::1') return true;
    // The first group decides: fc00::/7 (unique local) or fe80::/10 (link-local).
    // "fd1::" is 0x0fd1, which is neither, so the group is read as a number.
    const head = lower.split(':')[0] ?? '';
    if (!/^[0-9a-f]{1,4}$/.test(head)) return false;
    const first = parseInt(head, 16);
    return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
  }
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [a = 0, b = 0] = parts;
  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}
