import { flexRender, Row } from "@tanstack/react-table";
import { TableCell, TableRow } from "../ui/table";
import { cn } from "@/lib/utils";

type TableBodyRowProps<TData> = {
    row: Row<TData>;
    enableColumnFiltering?: boolean;
    cellClasses?: string;
};

export const TableBodyRow = <TData,>(props: TableBodyRowProps<TData>) => {
    const { row, enableColumnFiltering, cellClasses } = props;
    return (
        <TableRow
            onClick={() => {
                row.toggleSelected();
            }}>
            {row.getVisibleCells().map(cell => {
                return (
                    <TableCell
                        key={cell.id}
                        className={cn(
                            "px-6 py-4 transition-colors",
                            cellClasses,
                            cell.column.getIsFiltered() ? "bg-yellow-50" : ""
                        )}
                        onClick={event => {
                            if (!cell.column.getCanFilter() || !enableColumnFiltering)
                                return;
                            // Prevent user from selecting the whole row by clicking on a filterable column
                            event.stopPropagation();
                            cell.column.setFilterValue(cell.getValue());
                        }}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                );
            })}
        </TableRow>
    );
};
