export type NetworkProtocol = "TCP" | "UDP" | "ICMP" | "DNS";

export type NetworkLogEntry = {
  date: string;
  time: string;
  event: "NETWORK_CONNECTION";
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: NetworkProtocol;
  bytes: number;
  domain?: string;
};

export type InvalidNetworkLog = {
  line: string;
  reason: string;
};

export type NetworkParseResult = {
  entries: NetworkLogEntry[];
  invalidLogs: InvalidNetworkLog[];
};
