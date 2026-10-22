// =========================================
// DATE VALIDATION
// =========================================

export function isValidDate(
  date: string
): boolean {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})$/.exec(
      date
    );

  if (!match) {
    return false;
  }

  const year: number =
    Number(match[1]);

  const month: number =
    Number(match[2]);

  const day: number =
    Number(match[3]);

  const parsedDate =
    new Date(
      Date.UTC(
        year,
        month - 1,
        day
      )
    );

  return (
    parsedDate.getUTCFullYear() === year &&
    parsedDate.getUTCMonth() === month - 1 &&
    parsedDate.getUTCDate() === day
  );
}

// =========================================
// TIME VALIDATION
// =========================================

export function isValidTime(
  time: string
): boolean {
  return /^(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d$/.test(
    time
  );
}

// =========================================
// IPV4 VALIDATION
// =========================================

export function isValidIPv4(
  ipAddress: string
): boolean {
  const parts: string[] =
    ipAddress.split(".");

  if (parts.length !== 4) {
    return false;
  }

  return parts.every(
    (part: string) => {
      if (!/^\d{1,3}$/.test(part)) {
        return false;
      }

      const value: number =
        Number(part);

      return (
        value >= 0 &&
        value <= 255
      );
    }
  );
}
// =========================================
// PRIVATE IPV4 CHECK
// =========================================

export function isPrivateIPv4(ipAddress: string): boolean {
  if (!isValidIPv4(ipAddress)) return false;

  const [a, b] = ipAddress.split(".").map(Number);

  return (
    a === 10 ||
    (a === 172 && b! >= 16 && b! <= 31) ||
    (a === 192 && b === 168) ||
    a === 127
  );
}
