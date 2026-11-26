// Names of well-known ports, so "22" reads as "22 (SSH)". Only common
// services on home and small office networks are listed.

const SERVICES: Record<number, string> = {
  20: 'FTP data',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  137: 'NetBIOS',
  138: 'NetBIOS',
  139: 'NetBIOS',
  143: 'IMAP',
  161: 'SNMP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  554: 'RTSP',
  587: 'SMTP',
  631: 'IPP',
  853: 'DNS over TLS',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MS SQL',
  1883: 'MQTT',
  1900: 'SSDP',
  3306: 'MySQL',
  3389: 'RDP',
  5353: 'mDNS',
  5432: 'PostgreSQL',
  5900: 'VNC',
  8080: 'HTTP',
  8443: 'HTTPS',
};

export function serviceName(port: number): string | null {
  return SERVICES[port] ?? null;
}

/** "22 (SSH)" or just "40000". */
export function portLabel(port: number): string {
  const name = serviceName(port);
  return name ? `${port} (${name})` : String(port);
}
