import type { LogFile } from "../api";

export type LogFamily = {
  key: string;
  current: LogFile;
  generations: { gen: number; file: LogFile }[];
};

// Rotated copies share their base name plus a numeric suffix (logrotate
// convention: name.log, name.log.1, name.log.2, ...). Grouping by that base
// name keeps a rotated family to one table row instead of one row per copy.
export function groupLogFiles(files: LogFile[]): LogFamily[] {
  const families = new Map<
    string,
    { current: LogFile | null; generations: { gen: number; file: LogFile }[] }
  >();
  for (const file of files) {
    const match = file.name.match(/^(.*)\.(\d+)$/);
    const key = match ? match[1] : file.name;
    const entry = families.get(key) ?? { current: null, generations: [] };
    if (match) {
      entry.generations.push({ gen: Number(match[2]), file });
    } else {
      entry.current = file;
    }
    families.set(key, entry);
  }
  const result: LogFamily[] = [];
  for (const [key, entry] of families) {
    entry.generations.sort((a, b) => a.gen - b.gen);
    // A base file can be absent if rotation deleted it before the current one
    // was recreated; fall back to the oldest generation so the family isn't lost.
    const current = entry.current ?? entry.generations[0]?.file;
    if (!current) {
      continue;
    }
    result.push({
      key,
      current,
      generations: entry.generations.filter(({ file }) => file.name !== current.name)
    });
  }
  result.sort((a, b) => a.key.localeCompare(b.key));
  return result;
}
