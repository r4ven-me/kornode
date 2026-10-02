import { type ConfigSection, configSections } from "../../app/types";

export function ConfigSubnav({
  active,
  onSelect
}: {
  active: ConfigSection;
  onSelect: (section: ConfigSection) => void;
}) {
  return (
    <>
      <label className="subnav-select">
        <span>Config section</span>
        <select
          value={active}
          onChange={(event) => onSelect(event.target.value as ConfigSection)}
        >
          {configSections.map((item) => (
            <option key={item.id} value={item.id}>
              {item.label}
            </option>
          ))}
        </select>
      </label>
      <nav className="subnav" aria-label="Config sections">
        {configSections.map((item) => (
          <button
            key={item.id}
            type="button"
            className={active === item.id ? "subnav-item active" : "subnav-item"}
            onClick={() => onSelect(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>
    </>
  );
}
