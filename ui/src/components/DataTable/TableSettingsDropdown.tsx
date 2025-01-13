import { Table as ReactTable, Row } from "@tanstack/react-table";
import {
    DropdownMenu,
    DropdownMenuCheckboxItem,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "../ui/dropdown-menu";
import Button from "../Button";

type TableSettingsDropdownProps = {
    table: ReactTable<any>;
    deleteSelectedRowsCallback?: (selected: Row<any>[]) => void;
    addEntryCallback?: () => void;
};

export const TableSettingsDropdown = (props: TableSettingsDropdownProps) => {
    const { table, deleteSelectedRowsCallback, addEntryCallback } = props;

    const columns = table.getAllColumns();

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button variant={"outline"} size={"sm"}>
                    Controls
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
                <DropdownMenuLabel>Show columns</DropdownMenuLabel>
                {columns
                    .filter(col => col.getCanHide())
                    .map(col => {
                        return (
                            <DropdownMenuCheckboxItem
                                className="capitalize"
                                key={col.id}
                                checked={col.getIsVisible()}
                                onCheckedChange={col.toggleVisibility}>
                                {col.id}
                            </DropdownMenuCheckboxItem>
                        );
                    })}
                {(columns.some(col => col.getIsFiltered()) ||
                    table.getIsSomeRowsSelected() ||
                    table.getIsAllRowsSelected() ||
                    !!addEntryCallback) && (
                    <>
                        <DropdownMenuSeparator />
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        {columns.some(col => col.getIsFiltered()) && (
                            <DropdownMenuItem
                                onSelect={() => {
                                    table.resetColumnFilters();
                                }}>
                                Clear all filters
                            </DropdownMenuItem>
                        )}
                        {!!addEntryCallback && (
                            <DropdownMenuItem onSelect={() => addEntryCallback()}>
                                Add Entry
                            </DropdownMenuItem>
                        )}
                        {!!deleteSelectedRowsCallback &&
                            (table.getIsSomeRowsSelected() ||
                                table.getIsAllRowsSelected()) && (
                                <>
                                    <DropdownMenuItem
                                        onSelect={() => table.resetRowSelection()}>
                                        Deselect all rows
                                    </DropdownMenuItem>
                                    <DropdownMenuItem
                                        onSelect={() =>
                                            deleteSelectedRowsCallback(
                                                table.getSelectedRowModel().rows
                                            )
                                        }>
                                        Delete selected rows
                                    </DropdownMenuItem>
                                </>
                            )}
                    </>
                )}
            </DropdownMenuContent>
        </DropdownMenu>
    );
};
