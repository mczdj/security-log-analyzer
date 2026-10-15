// =========================================
// AUTHENTICATION LOG ENTRY
// =========================================

export type LogEntry = {
  date: string;
  time: string;
  event: string;
  username: string;
  ipAddress: string;
};

// =========================================
// INVALID AUTHENTICATION LOG
// =========================================

export type InvalidLog = {
  line: string;
  reason: string;
};

// =========================================
// AUTHENTICATION PARSER RESULT
// =========================================

export type ParseResult = {
  entries: LogEntry[];
  invalidLogs: InvalidLog[];
};

// =========================================
// AUTHENTICATION ANALYSIS
// =========================================

export type AuthenticationAnalysis = {
  successfulLogins: number;

  failedLogins: number;

  failedLoginCounts:
    Record<string, number>;

  failedLoginTimes:
    Record<string, number[]>;

  failedUsersByIp:
    Record<string, Set<string>>;

  failedIpsByUser:
    Record<string, Set<string>>;
};