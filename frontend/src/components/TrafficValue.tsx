import { formatTraffic, formatTrafficRate } from "../lib/format";

export function TrafficValue({ value, rate }: { value: string | null; rate?: string | null }) {
  return (
    <span className="traffic-value">
      <strong>{formatTraffic(value)}</strong>
      {rate ? <small>{formatTrafficRate(rate)}</small> : null}
    </span>
  );
}
