import { ColumnDef, Row } from "@tanstack/react-table";
import { Table, TableBody, TableHeader } from "../ui/table";
import { useState } from "react";
import { PaginationControls } from "./PaginationControls";
import { TopControls } from "./TopControls";
import { TableHeaderRow } from "./TableHeaderRow";
import { TableBodyRow } from "./TableBodyRow";
import { useTable } from "./useTable";

export type DataTableProps<TData, TValue> = {
    columns: ColumnDef<TData, TValue>[];
    data: TData[];
    defaultPageSize?: number;
    pageSizes?: number[];
    showPaginationControls?: boolean;
    showColumnVisibilityControls?: boolean;
    enableSorting?: boolean;
    enableFuzzySearch?: boolean;
    enableColumnFiltering?: boolean;
    tableContainerClasses?: string;
    cellClasses?: string;
    addEntryCallback?: () => void;
    deleteSelectedRowsCallback?: (selected: Row<TData>[]) => void;
    rowIdKey?: keyof TData;
    rowActions?: {
        label: string;
        callback: (row: Row<TData>) => void;
    }[];
    fullWidth?: boolean;
};

export default function DataTable<TData, TValue>(props: DataTableProps<TData, TValue>) {
    const {
        columns: columnsRaw,
        data,
        defaultPageSize,
        pageSizes = [5, 10, 50, 100],
        showPaginationControls = false,
        showColumnVisibilityControls = false,
        enableSorting,
        enableFuzzySearch = false,
        enableColumnFiltering,
        tableContainerClasses,
        cellClasses,
        addEntryCallback,
        deleteSelectedRowsCallback,
        rowActions: actions,
        fullWidth = false,
    } = props;

    const [isPageDialogOpen, setIsPageDialogOpen] = useState(false);

    const [table, pagination, setGlobalFilterDebounced] = useTable(
        columnsRaw,
        data,
        pageSizes,
        !!deleteSelectedRowsCallback,
        defaultPageSize,
        actions
    );

    return (
        <div
            className={`flex flex-1 flex-col justify-center mx-auto gap-6 ${fullWidth ? "" : "sm:w-2/3"}`}>
            <TopControls
                table={table}
                controls={[
                    showPaginationControls,
                    enableFuzzySearch,
                    showColumnVisibilityControls,
                ]}
                pageSizes={pageSizes}
                setPaginationCallback={pageSize => {
                    table.setPageSize(pageSize);
                }}
                onFuzzyFilterChange={value => setGlobalFilterDebounced(value)}
                addEntryCallback={addEntryCallback}
                deleteSelectedRowsCallback={deleteSelectedRowsCallback}
            />
            <div className={tableContainerClasses}>
                <Table>
                    <TableHeader>
                        {table.getHeaderGroups().map(group => {
                            return (
                                <TableHeaderRow
                                    key={group.id}
                                    group={group}
                                    enableSorting={enableSorting}
                                    cellClasses={cellClasses}
                                />
                            );
                        })}
                    </TableHeader>
                    <TableBody>
                        {table.getRowModel().rows.map(row => {
                            return (
                                <TableBodyRow
                                    key={row.id}
                                    row={row}
                                    enableColumnFiltering={enableColumnFiltering}
                                    cellClasses={cellClasses}
                                />
                            );
                        })}
                    </TableBody>
                </Table>
            </div>
            {showPaginationControls && (
                <PaginationControls
                    totalPages={table.getPageCount()}
                    currentPage={pagination.pageIndex}
                    isDialogOpen={isPageDialogOpen}
                    setIsDialogOpen={setIsPageDialogOpen}
                    setNewPage={page => table.setPageIndex(page)}
                    locationText={`Showing entries ${pagination.pageIndex * pagination.pageSize + 1} - ${Math.min(table.getRowCount(), pagination.pageIndex * pagination.pageSize + pagination.pageSize)} (of ${table.getRowCount()})`}
                />
            )}
        </div>
    );
}
