// The JSON the API returns. These mirror the Rust types in
// product/core/crates/flagman-store/src/rows.rs and flagman-core/src/health.rs.
// Times are milliseconds since 1970 (UTC).

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type IncidentStatus = 'open' | 'confirmed' | 'false_positive' | 'resolved';
export type AlertKind = 'port_scan' | 'host_sweep' | 'brute_force' | 'signature';
export type Protocol = 'tcp' | 'udp' | 'icmp' | 'other';
export type TrafficClass = 'tcp' | 'udp' | 'icmp' | 'arp' | 'other';
export type RangeLabel = '15m' | '1h' | '6h' | '24h' | '7d' | '30d';

export interface SuricataHealth {
  enabled: boolean;
  eve_path: string | null;
  reading: boolean;
  hits: number;
  last_error: string | null;
}

export interface Health {
  version: string;
  mode: 'live' | 'replay';
  source: string;
  started_at: number;
  last_packet_at: number | null;
  packets: number;
  bytes: number;
  packets_skipped: number;
  kernel_received: number | null;
  kernel_dropped: number | null;
  flows_active: number;
  flows_untracked: number;
  suricata: SuricataHealth;
  storage_errors: number;
  running: boolean;
  server_time: number;
  /** "latest_data" in replay mode: ranges end at the newest record. */
  clock: 'live' | 'latest_data';
}

export type SeverityCounts = Record<Severity, number>;
export type ClassCounts = Record<TrafficClass, number>;

export interface Overview {
  since: number;
  until: number;
  open_incidents: number;
  incidents: number;
  incidents_by_severity: SeverityCounts;
  alerts: number;
  flows: number;
  packets: number;
  bytes: number;
  local_hosts: number;
}

export interface TrafficPoint {
  t: number;
  bytes: ClassCounts;
  packets: ClassCounts;
}

export interface AlertPoint extends SeverityCounts {
  t: number;
}

export interface TalkerRow {
  ip: string;
  bytes: number;
  flows: number;
}

export interface NamedCount {
  name: string;
  detail: string | null;
  count: number;
  value: unknown;
}

export interface IncidentRow {
  id: number;
  first_seen: number;
  last_seen: number;
  src_ip: string;
  severity: Severity;
  alert_count: number;
  kinds: AlertKind[];
  tactics: string[];
  targets: string[];
  status: IncidentStatus;
}

export interface AttackRef {
  tactic: string;
  tactic_id: string;
  technique: string;
  technique_id: string;
}

export type AlertDetails =
  | { type: 'port_scan'; protocol: Protocol; ports_sample: number[]; window_secs: number }
  | { type: 'host_sweep'; method: 'arp' | 'icmp' | 'tcp' | 'udp'; hosts_sample: string[]; window_secs: number }
  | { type: 'brute_force'; service_port: number; window_secs: number }
  | { type: 'signature'; signature_id: number; signature: string; category: string; engine: string };

export interface AlertRow {
  id: number;
  incident_id: number | null;
  kind: AlertKind;
  severity: Severity;
  first_seen: number;
  last_seen: number;
  src_ip: string;
  dst_ip: string | null;
  dst_port: number | null;
  count: number;
  details: AlertDetails;
  attack: AttackRef | null;
}

export interface FlowRow {
  id: number;
  first_seen: number;
  last_seen: number;
  protocol: Protocol;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  packets_fwd: number;
  packets_rev: number;
  bytes_fwd: number;
  bytes_rev: number;
  tcp_outcome: 'established' | 'half_open' | 'rejected' | 'unanswered' | 'midstream' | null;
}

export interface IncidentDetail {
  incident: IncidentRow;
  alerts: AlertRow[];
  flows: FlowRow[];
  flows_truncated: boolean;
}

export interface Dashboard {
  range: { label: RangeLabel; since: number; until: number; bucket_ms: number };
  overview: Overview;
  traffic: TrafficPoint[];
  alerts: AlertPoint[];
  top_talkers: TalkerRow[];
  top_ports: NamedCount[];
  top_alerts: NamedCount[];
  protocol_packets: ClassCounts;
  protocol_bytes: ClassCounts;
  recent_incidents: IncidentRow[];
}
