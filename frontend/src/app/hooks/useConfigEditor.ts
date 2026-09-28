import { useState } from "react";
import { fetchConfigDiff, saveConfigSource, validateConfigSource } from "../../api";
import type { PanelCore } from "../core";

// The raw YAML editor under Config → Advanced.
export function useConfigEditor(core: PanelCore) {
  const { authToken, loadAll, runAction, setState, state } = core;
  const [configDraft, setConfigDraft] = useState("");
  const [configDirty, setConfigDirty] = useState(false);
  const [configDiff, setConfigDiff] = useState("");
  const [configValidation, setConfigValidation] = useState("");

  core.registerHydrator("configEditor", ({ configSource }) => {
    // Never clobber unsaved edits with a background reload.
    if (!configDirty && configSource) {
      setConfigDraft(configSource.content);
    }
  });

  const editDraft = (value: string) => {
    setConfigDraft(value);
    setConfigDirty(true);
  };

  const reloadSource = () => {
    setConfigDraft(state.configSource?.content ?? "");
    setConfigDirty(false);
    setConfigValidation("");
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
      (token) => saveConfigSource(token, configDraft, true),
      { reload: false }
    );
    if (result && authToken) {
      setConfigDraft(result.content);
      setConfigDirty(false);
      setState((current) => ({
        ...current,
        config: result.config,
        configSource: {
          path: result.path,
          exists: true,
          content: result.content
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
    editDraft,
    reloadSource,
    validate,
    diff,
    save
  };
}
