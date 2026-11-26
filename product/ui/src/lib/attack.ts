// Links to the MITRE ATT&CK knowledge base (https://attack.mitre.org).

/** "T1046" -> its page; "T1110.001" -> the sub-technique page. */
export function techniqueUrl(id: string): string | null {
  const match = /^T(\d{4})(?:\.(\d{3}))?$/.exec(id);
  if (!match) return null;
  const sub = match[2] ? `${match[2]}/` : '';
  return `https://attack.mitre.org/techniques/T${match[1]}/${sub}`;
}

export function tacticUrl(id: string): string | null {
  return /^TA\d{4}$/.test(id) ? `https://attack.mitre.org/tactics/${id}/` : null;
}
