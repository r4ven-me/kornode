import { type FormEvent, useState } from "react";
import {
  type CertificateInfoResponse,
  type CertificatePin,
  type IntervalUnit,
  fetchAuthorityCertificateInfo,
  fetchLetsEncryptCertificateInfo,
  fetchRevokedCertificates,
  fetchServerCertificateInfo,
  fetchServerCertificatePin,
  issueLetsEncryptCertificate,
  regenerateCa,
  renewLetsEncryptCertificate,
  revokeCaCertificateB64,
  revokeCaCertificateFile,
  saveCertificateSettings,
  saveLetsEncryptSettings,
  uploadCa,
  uploadExternalCertificates
} from "../../api";
import { confirmAction } from "../../lib/async";
import { splitLines } from "../../lib/drafts";
import type { PanelCore } from "../core";
import type { CertificateContentModalState, RevokedCertsModalState } from "../types";

export function useCertificates(core: PanelCore) {
  const { authToken, dryRun, loadAll, recordCommand, runAction, runBusyTask, setNotice } = core;
  const [externalCertFiles, setExternalCertFiles] = useState<{
    serverCert: File | null;
    serverKey: File | null;
    caCert: File | null;
  }>({ serverCert: null, serverKey: null, caCert: null });
  const [caFiles, setCaFiles] = useState<{ caCert: File | null; caKey: File | null }>({
    caCert: null,
    caKey: null
  });
  const [caRevokeDraft, setCaRevokeDraft] = useState<{
    certificateB64: string;
    certificateFile: File | null;
  }>({ certificateB64: "", certificateFile: null });
  const [certificateSettingsDraft, setCertificateSettingsDraft] = useState<{
    mode: "auto" | "external";
    caName: string;
  }>({ mode: "auto", caName: "Korvus Node CA" });
  const [letsEncryptDraft, setLetsEncryptDraft] = useState({
    enabled: false,
    email: "",
    domains: "",
    staging: false,
    reload: true,
    autoRenew: true,
    interval: 7,
    intervalUnit: "days" as IntervalUnit,
    http01Address: "",
    http01Port: 80
  });
  const [revokedCertsModal, setRevokedCertsModal] = useState<RevokedCertsModalState>(null);
  const [serverPin, setServerPin] = useState<CertificatePin | null>(null);
  const [certificateContentModal, setCertificateContentModal] =
    useState<CertificateContentModalState>(null);

  core.registerHydrator("certificates", ({ certificateStatus: status }) => {
    if (!status) {
      return;
    }
    setCertificateSettingsDraft({
      mode: status.mode === "external" ? "external" : "auto",
      caName: status.ca_name
    });
    setLetsEncryptDraft((current) => ({
      ...current,
      enabled: status.letsencrypt.enabled,
      email: status.letsencrypt.email ?? "",
      domains: status.letsencrypt.domains.join("\n"),
      reload: status.letsencrypt.renew_reload,
      autoRenew: status.letsencrypt.auto_renew_enabled,
      interval: status.letsencrypt.auto_renew_interval,
      intervalUnit: status.letsencrypt.auto_renew_interval_unit,
      http01Address: status.letsencrypt.http01_address ?? "",
      http01Port: status.letsencrypt.http01_port
    }));
  });

  const uploadExternal = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!externalCertFiles.serverCert || !externalCertFiles.serverKey || !externalCertFiles.caCert) {
      setNotice({ kind: "error", text: "select server certificate, server key and CA certificate" });
      return;
    }
    const result = await runAction(
      "cert-upload",
      "External certificates installed",
      (token) =>
        uploadExternalCertificates(
          token,
          {
            serverCert: externalCertFiles.serverCert as File,
            serverKey: externalCertFiles.serverKey as File,
            caCert: externalCertFiles.caCert as File
          },
          letsEncryptDraft.reload
        ),
      { reload: false }
    );
    recordCommand("certificates", result?.reload ?? null);
    if (result !== null && authToken) {
      setExternalCertFiles({ serverCert: null, serverKey: null, caCert: null });
      await loadAll(authToken);
    }
  };

  const issueLetsEncrypt = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const domains = splitLines(letsEncryptDraft.domains);
    const result = await runAction(
      "le-issue",
      "Let's Encrypt certificate issued",
      (token) =>
        issueLetsEncryptCertificate(token, {
          email: letsEncryptDraft.email,
          domains,
          staging: letsEncryptDraft.staging,
          reload: letsEncryptDraft.reload,
          auto_renew_enabled: letsEncryptDraft.autoRenew,
          auto_renew_interval: letsEncryptDraft.interval,
          auto_renew_interval_unit: letsEncryptDraft.intervalUnit,
          dry_run: dryRun
        }),
      { reload: false, dryRunAware: true }
    );
    recordCommand(
      "certificates",
      result ? [result.result, ...(result.reload ? [result.reload] : [])] : null
    );
    if (result !== null && authToken && !dryRun) {
      await loadAll(authToken);
    }
  };

  const renewLetsEncrypt = async () => {
    const result = await runAction(
      "le-renew",
      "Let's Encrypt renewal completed",
      (token) => renewLetsEncryptCertificate(token, letsEncryptDraft.reload, dryRun),
      { reload: false, dryRunAware: true }
    );
    recordCommand(
      "certificates",
      result ? [result.result, ...(result.reload ? [result.reload] : [])] : null
    );
    if (result !== null && authToken && !dryRun) {
      await loadAll(authToken);
    }
  };

  const saveLetsEncryptSettingsAction = async (enabled = letsEncryptDraft.enabled) => {
    const domains = splitLines(letsEncryptDraft.domains);
    const result = await runAction(
      "le-settings",
      "Let's Encrypt settings saved",
      (token) =>
        saveLetsEncryptSettings(token, {
          enabled,
          email: letsEncryptDraft.email.trim() || null,
          domains,
          renew_reload: letsEncryptDraft.reload,
          auto_renew_enabled: letsEncryptDraft.autoRenew,
          auto_renew_interval: letsEncryptDraft.interval,
          auto_renew_interval_unit: letsEncryptDraft.intervalUnit,
          http01_address: letsEncryptDraft.http01Address.trim() || null,
          http01_port: letsEncryptDraft.http01Port
        }),
      { reload: false }
    );
    if (result !== null && authToken) {
      await loadAll(authToken);
    }
  };

  const setLetsEncryptEnabled = async (enabled: boolean) => {
    setLetsEncryptDraft((current) => ({ ...current, enabled }));
    await saveLetsEncryptSettingsAction(enabled);
  };

  const saveSettings = async () => {
    const result = await runAction(
      "certificate-settings",
      "Certificate settings saved",
      (token) =>
        saveCertificateSettings(token, {
          mode: certificateSettingsDraft.mode,
          ca_name: certificateSettingsDraft.caName
        }),
      { reload: false }
    );
    if (result !== null && authToken) {
      await loadAll(authToken);
    }
  };

  const regenerateCaAction = async () => {
    if (!confirmAction("Regenerate the CA? Existing client certificates may need reissue.")) {
      return;
    }
    const result = await runAction(
      "ca-regenerate",
      "CA regenerated",
      (token) => regenerateCa(token, dryRun),
      { reload: false, dryRunAware: true }
    );
    recordCommand("certificates", result?.results ?? null);
  };

  const uploadCaAction = async () => {
    if (!caFiles.caCert || !caFiles.caKey) {
      setNotice({ kind: "error", text: "select CA certificate and CA private key" });
      return;
    }
    const result = await runAction(
      "ca-upload",
      "CA material uploaded",
      (token) =>
        uploadCa(token, {
          caCert: caFiles.caCert as File,
          caKey: caFiles.caKey as File
        }),
      { reload: false }
    );
    recordCommand("certificates", result);
    if (result) {
      setCaFiles({ caCert: null, caKey: null });
    }
  };

  const revokeCaCert = async () => {
    const result = await runAction(
      "ca-revoke",
      "Certificate revoked",
      (token) =>
        caRevokeDraft.certificateFile
          ? revokeCaCertificateFile(token, caRevokeDraft.certificateFile, dryRun)
          : revokeCaCertificateB64(token, window.btoa(caRevokeDraft.certificateB64.trim()), dryRun),
      { reload: false, dryRunAware: true }
    );
    recordCommand("certificates", result);
    if (result && !dryRun) {
      setCaRevokeDraft({ certificateB64: "", certificateFile: null });
    }
  };

  // Pin other openconnect clients (an upstream profile on another kornode)
  // use to trust this server's certificate.
  const showServerPin = async () => {
    const result = await runAction(
      "server-pin",
      "Server certificate pin loaded",
      fetchServerCertificatePin,
      { reload: false }
    );
    setServerPin(result);
  };

  const showRevokedCerts = async () => {
    setRevokedCertsModal({ loading: true, certificates: [] });
    if (!authToken) {
      return;
    }
    try {
      const { certificates } = await fetchRevokedCertificates(authToken);
      setRevokedCertsModal({ loading: false, certificates });
    } catch {
      setRevokedCertsModal({ loading: false, certificates: [] });
      setNotice({ kind: "error", text: "failed to load revoked certificates" });
    }
  };

  const showCertificateContent = (
    key: string,
    title: string,
    fetcher: (token: string) => Promise<CertificateInfoResponse>
  ) => {
    setCertificateContentModal({ title, loading: true, path: "", certificate: null });
    return runBusyTask(key, async (token) => {
      try {
        const { path, certificate } = await fetcher(token);
        setCertificateContentModal({ title, loading: false, path, certificate });
      } catch (error) {
        setCertificateContentModal({ title, loading: false, path: "", certificate: null });
        throw error;
      }
    });
  };

  const showAuthorityCertificateContent = () =>
    showCertificateContent("authority-cert-info", "Certificate authority", fetchAuthorityCertificateInfo);
  const showServerCertificateContent = () =>
    showCertificateContent("server-cert-info", "Server certificate", fetchServerCertificateInfo);
  const showLetsEncryptCertificateContent = () =>
    showCertificateContent(
      "letsencrypt-cert-info",
      "Let's Encrypt certificate",
      fetchLetsEncryptCertificateInfo
    );

  return {
    externalCertFiles,
    setExternalCertFiles,
    caFiles,
    setCaFiles,
    caRevokeDraft,
    setCaRevokeDraft,
    certificateSettingsDraft,
    setCertificateSettingsDraft,
    letsEncryptDraft,
    setLetsEncryptDraft,
    revokedCertsModal,
    closeRevokedCerts: () => setRevokedCertsModal(null),
    uploadExternal,
    issueLetsEncrypt,
    renewLetsEncrypt,
    saveLetsEncryptSettings: saveLetsEncryptSettingsAction,
    setLetsEncryptEnabled,
    saveSettings,
    regenerateCa: regenerateCaAction,
    uploadCa: uploadCaAction,
    revokeCaCert,
    showRevokedCerts,
    serverPin,
    showServerPin,
    certificateContentModal,
    closeCertificateContent: () => setCertificateContentModal(null),
    showAuthorityCertificateContent,
    showServerCertificateContent,
    showLetsEncryptCertificateContent
  };
}
