import { queryColumns } from "@/lib/types";
import DataTable from "./DataTable";
import { useQueryLogs } from "@/common/useQueryLogs";
import { FullScreenLoader } from "./FullScreenLoader";

const QueryLog = () => {
    const { data } = useQueryLogs();

    return data ? (
        <DataTable
            columns={queryColumns}
            data={data}
            defaultPageSize={20}
            pageSizes={[10, 20, 50, 100]}
            enableSorting
            showPaginationControls
            showColumnVisibilityControls
            enableFuzzySearch
            enableColumnFiltering
            tableContainerClasses="rounded-md border"
        />
    ) : (
        <FullScreenLoader />
    );
};

export default QueryLog;
