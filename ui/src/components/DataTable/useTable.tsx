import useDebounced from "@/common/useDebounced";
import {
    ColumnDef,
    getCoreRowModel,
    getFilteredRowModel,
    getPaginationRowModel,
    getSortedRowModel,
    PaginationState,
    Row,
    useReactTable,
} from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { Checkbox } from "../ui/checkbox";
import { fuzzyFilterFn } from "./utils";
import { DataTableActions } from "./DataTableActions";

export const useTable = <TData, TValue>(
    columnsRaw: ColumnDef<TData, TValue>[],
    data: TData[],
    pageSizes: number[],
    deleteSelectedRowsCb: boolean,
    defaultPageSize?: number,
    actions?: {
        label: string;
        callback: (row: Row<TData>) => void;
    }[]
) => {
    const [pagination, setPagination] = useState<PaginationState>({
        pageIndex: 0,
        pageSize: defaultPageSize ?? pageSizes[0] ?? 5,
    });

    const {
        state: globalFilterDebounced,
        setStateDebounced: setGlobalFilterDebounced,
        setState: setGlobalFilter,
    } = useDebounced<string>(500, "");

    const columns = useMemo(() => {
        const columns: ColumnDef<TData, TValue>[] = [];

        if (!!deleteSelectedRowsCb) {
            columns.push({
                id: "__checkbox__",
                header: ({ table }) => (
                    <Checkbox
                        onClick={table.getToggleAllRowsSelectedHandler()}
                        checked={table.getIsAllRowsSelected()}
                    />
                ),
                cell: ({ row }) => (
                    <Checkbox
                        checked={row.getIsSelected()}
                        disabled={!row.getCanSelect()}
                        onCheckedChange={row.getToggleSelectedHandler()}
                    />
                ),
                enableHiding: false,
            });
        }

        columns.push(...columnsRaw);

        if (actions?.length) {
            columns.push({
                id: "__actions__",
                cell: ({ row }) => <DataTableActions actions={actions} row={row} />,
                enableHiding: false,
            });
        }

        return columns;
    }, [actions, columnsRaw, deleteSelectedRowsCb]);

    const table = useReactTable<TData>({
        columns,
        data,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
        globalFilterFn: fuzzyFilterFn,
        onPaginationChange: setPagination,
        onGlobalFilterChange: setGlobalFilter,
        enableRowSelection: deleteSelectedRowsCb,
        state: {
            pagination,
            globalFilter: globalFilterDebounced,
        },
    });

    return { table, pagination, setGlobalFilterDebounced };
};
