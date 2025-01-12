import { flexRender, HeaderGroup } from "@tanstack/react-table";
import { TableHead, TableRow } from "../ui/table";
import { cn } from "@/lib/utils";
import { SortDirection } from "@tanstack/react-table";
import { ArrowDownNarrowWide, ArrowUpDown, ArrowUpWideNarrow } from "lucide-react";

const SortingIcon = ({
    sortDirection,
    size,
}: {
    sortDirection: false | SortDirection;
    size: number;
}) => {
    if (!sortDirection) return <ArrowUpDown size={size} />;
    if (sortDirection === "asc") return <ArrowDownNarrowWide size={size} />;
    return <ArrowUpWideNarrow size={size} />;
};

type TableHeaderRowProps = {
    group: HeaderGroup<any>;
    enableSorting?: boolean;
    cellClasses?: string;
};

export const TableHeaderRow = (props: TableHeaderRowProps) => {
    const { group, enableSorting, cellClasses } = props;

    return (
        <TableRow>
            {group.headers.map(header => (
                <TableHead
                    className={cn(
                        "p-6 transition-colors",
                        cellClasses,
                        header.column.getIsFiltered() ? "bg-yellow-50" : ""
                    )}
                    key={header.id}
                    onClick={
                        enableSorting && header.column.getCanSort()
                            ? header.column.getToggleSortingHandler()
                            : undefined
                    }>
                    <div className="flex flex-row gap-2 items-center">
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        {enableSorting && header.column.getCanSort() && (
                            <SortingIcon
                                size={16}
                                sortDirection={header.column.getIsSorted()}
                            />
                        )}
                    </div>
                </TableHead>
            ))}
        </TableRow>
    );
};
