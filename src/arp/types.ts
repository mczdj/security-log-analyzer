export type ArpLogEntry = {
  date: string;
  time: string;
  event: "ARP_REPLY";
  ipAddress: string;
  macAddress: string;
};

export type InvalidArpLog = {
  line: string;
  reason: string;
};

export type ArpParseResult = {
  entries: ArpLogEntry[];
  invalidLogs: InvalidArpLog[];
};
