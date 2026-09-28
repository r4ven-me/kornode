import type { ReactNode } from "react";

export function Table({
  columns,
  children,
  empty
}: {
  columns: string[];
  children: ReactNode;
  empty: string;
}) {
  const rows = Array.isArray(children) ? children.filter(Boolean).length : children ? 1 : 0;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows ? (
            children
          ) : (
            <tr>
              <td className="empty-cell" colSpan={columns.length}>
                {empty}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
