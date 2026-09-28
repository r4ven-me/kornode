import { type ConfigSection, configSections } from "../../app/types";

export function ConfigSubnav({
  active,
  onSelect
}: {
  active: ConfigSection;
  onSelect: (section: ConfigSection) => void;
}) {
  return (
    <nav className="subnav">
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
  );
}
