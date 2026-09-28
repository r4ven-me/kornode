import { Pill } from "../../components/ui";
import type { CertificatePathStatus } from "../../api";

export function CertificatePathsView({
  paths,
  caLabel = "CA chain"
}: {
  paths: CertificatePathStatus;
  caLabel?: string;
}) {
  return (
    <div className="cert-paths">
      <PathRow label="Certificate" path={paths.server_cert} ok={paths.server_cert_exists} />
      <PathRow label="Private key" path={paths.server_key} ok={paths.server_key_exists} />
      <PathRow label={caLabel} path={paths.ca_cert} ok={paths.ca_cert_exists} />
    </div>
  );
}

export function AuthorityPathsView({
  authority
}: {
  authority: { ca_cert: string; ca_key: string; ca_cert_exists: boolean; ca_key_exists: boolean };
}) {
  return (
    <div className="cert-paths authority-paths">
      <PathRow label="CA certificate" path={authority.ca_cert} ok={authority.ca_cert_exists} />
      <PathRow label="CA private key" path={authority.ca_key} ok={authority.ca_key_exists} />
    </div>
  );
}

export function PathRow({ label, path, ok }: { label: string; path: string; ok: boolean }) {
  return (
    <div className="path-row">
      <strong>{label}</strong>
      <Pill kind={ok ? "ok" : "warning"}>{ok ? "Found" : "Missing"}</Pill>
      <code>{path}</code>
    </div>
  );
}
