import { Children, type ReactElement, type ReactNode, isValidElement, useState } from "react";

// Renders each child section as a tab (its <summary> is the tab label).
export function SettingsTabs({ children, ariaLabel }: { children: ReactNode; ariaLabel: string }) {
  const items = Children.toArray(children).filter(isValidElement) as ReactElement<{
    children?: ReactNode;
  }>[];
  const [activeIndex, setActiveIndex] = useState(0);
  const safeIndex = Math.min(activeIndex, Math.max(0, items.length - 1));
  const activeItem = items[safeIndex];
  const activeChildren = activeItem ? Children.toArray(activeItem.props.children) : [];

  return (
    <div className="settings-tabs">
      <div className="settings-tab-list" role="tablist" aria-label={ariaLabel}>
        {items.map((item, index) => {
          const itemChildren = Children.toArray(item.props.children);
          const summary = itemChildren[0];
          const label = isValidElement(summary) ? summary.props.children : `Section ${index + 1}`;
          return (
            <button
              aria-selected={safeIndex === index}
              className={safeIndex === index ? "settings-tab active" : "settings-tab"}
              key={index}
              onClick={() => setActiveIndex(index)}
              role="tab"
              type="button"
            >
              {label}
            </button>
          );
        })}
      </div>
      {activeItem && (
        <div className="settings-tab-panel" role="tabpanel">
          {activeChildren.slice(1)}
        </div>
      )}
    </div>
  );
}
