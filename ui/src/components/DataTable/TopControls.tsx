import { useMemo } from "react";
import { Input } from "../ui/input";
import Button from "../Button";
import { Table as ReactTable, Row } from "@tanstack/react-table";
import { PaginationSelector } from "./PaginationSelector";
import { TableSettingsDropdown } from "./TableSettingsDropdown";
import useWindowDimensions from "@/common/useWindowDimensions";

type TopControlsProps = {
    table: ReactTable<any>;
    controls: [boolean, boolean, boolean];
    pageSizes: number[];
    setPaginationCallback: (pageSize: number) => void;
    onFuzzyFilterChange: (value: string) => void;
    addEntryCallback?: () => void;
    deleteSelectedRowsCallback?: (selected: Row<any>[]) => void;
};

export const TopControls = (props: TopControlsProps) => {
    const {
        table,
        controls,
        pageSizes,
        setPaginationCallback,
        onFuzzyFilterChange,
        addEntryCallback,
        deleteSelectedRowsCallback,
    } = props;

    const [showPaginationControls, enableFuzzySearch, showTableSettings] = controls;

    const dimensions = useWindowDimensions();
    const enabledControls = useMemo(() => controls.filter(Boolean).length, [controls]);

    return enabledControls ? (
        <div
            className={`flex flex-row items-center ${enabledControls > 1 ? "justify-between" : !showPaginationControls ? "justify-end" : ""}`}>
            {showPaginationControls && (
                <PaginationSelector
                    pageSizes={pageSizes}
                    currentPageSize={table.getState().pagination.pageSize}
                    setter={setPaginationCallback}
                />
            )}
            {enableFuzzySearch && (
                <Input
                    className="w-1/3"
                    placeholder="Search..."
                    onFocus={event => (event.target.placeholder = "")}
                    onBlur={event => (event.target.placeholder = "Search...")}
                    onChange={event => onFuzzyFilterChange(event.target.value)}
                />
            )}
            {showTableSettings && (
                <TableSettingsDropdown
                    table={table}
                    deleteSelectedRowsCallback={deleteSelectedRowsCallback}
                    addEntryCallback={
                        dimensions.width >= 768 ? undefined : addEntryCallback
                    }
                />
            )}
            {dimensions.width >= 768 && addEntryCallback && (
                <Button
                    variant={"primary"}
                    size={"sm"}
                    className="px-6 rounded-md"
                    onClick={addEntryCallback}>
                    Add Entry
                </Button>
            )}
        </div>
    ) : (
        <></>
    );
};
