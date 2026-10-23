import { useState } from "react";
import { ApiError, fetchConfigDiff, fetchConfigSource, saveConfigSource, validateConfigSource } from "../../api";
import { confirmAction } from "../../lib/async";
import type { PanelCore } from "../core";

// The raw YAML editor under Config → Advanced.
export function useConfigEditor(core: PanelCore) {
  const { authToken, loadAll, runAction, setState } = core;
  const [configDraft, setConfigDraft] = useState("");
  const [configDirty, setConfigDirty] = useState(false);
  const [configDiff, setConfigDiff] = useState("");
  const [configValidation, setConfigValidation] = useState("");
  const [configEtag, setConfigEtag] = useState<string | null>(null);
  const [configConflict, setConfigConflict] = useState("");

  core.registerHydrator("configEditor", ({ configSource }) => {
    // Never clobber unsaved edits with a background reload.
    if (!configDirty && configSource) {
      setConfigDraft(configSource.content);
      setConfigEtag(configSource.etag);
    }
  });

  const editDraft = (value: string) => {
    setConfigDraft(value);
    setConfigDirty(true);
  };

  const reloadSource = async () => {
    if (configDirty && !confirmAction("Discard unsaved YAML edits and fetch the latest source? Copy any edits you want to keep before reloading.")) return;
    const source = await runAction("config-source-reload", "Latest config source loaded", fetchConfigSource, { reload: false });
    if (!source) return;
    setConfigDraft(source.content);
    setConfigEtag(source.etag);
    setConfigDirty(false);
    setConfigConflict("");
    setConfigValidation("");
    setState(current => ({ ...current, configSource: source }));
  };

  const validate = async () => {
    const result = await runAction(
      "config-validate",
      "Config validated",
      (token) => validateConfigSource(token, configDraft),
      { reload: false }
    );
    setConfigValidation(result ? JSON.stringify(result, null, 2) : "");
  };

  const diff = async () => {
    const result = await runAction("config-diff", "Config diff loaded", fetchConfigDiff, {
      reload: false
    });
    setConfigDiff(result?.diff ?? "");
  };

  const save = async () => {
    const result = await runAction(
      "config-save",
      "Config saved",
      async (token) => {
        try {
          return await saveConfigSource(token, configDraft, true, configEtag ?? "");
        } catch (error) {
          if (error instanceof ApiError && (error.status === 412 || error.status === 428)) {
            setConfigConflict(error.status === 412
              ? "The YAML source changed on disk. Your edits are preserved and were not saved. Copy or reconcile them before using Reload to discard this draft and fetch the latest source."
              : "The source version is missing. Your edits are preserved and were not saved. Copy them before using Reload to fetch a versioned source.");
          }
          throw error;
        }
      },
      { reload: false }
    );
    if (result && authToken) {
      setConfigDraft(result.content);
      setConfigEtag(result.etag);
      setConfigConflict("");
      setConfigDirty(false);
      setState((current) => ({
        ...current,
        config: result.config,
        configSource: {
          path: result.path,
          exists: true,
          content: result.content,
          etag: result.etag
        }
      }));
      await loadAll(authToken);
    }
  };

  return {
    configDraft,
    configDirty,
    configDiff,
    configValidation,
    configConflict,
    editDraft,
    reloadSource,
    validate,
    diff,
    save
  };
}
