import { ColumnDef } from "@tanstack/react-table";
import { formatDate } from "./utils";
import { DNS_QUERY_TYPES, RESPONSE_SOURCES } from "./constants";

export interface Query {
    id: number;
    timestamp: number;
    domain: string;
    qtype: number;
    client?: string;
    response_code: number;
    response_delay_ms?: number;
    source?: number;
}

export const queryColumns: ColumnDef<Query>[] = [
    {
        accessorKey: "timestamp",
        header: "Time",
        cell({ cell }) {
            return formatDate((cell.getValue() as number) * 1000);
        },
        enableColumnFilter: false,
        enableGlobalFilter: false,
    },
    {
        accessorKey: "qtype",
        filterFn: "equals",
        cell({ cell }) {
            const qtype = cell.getValue() as string;
            return DNS_QUERY_TYPES[qtype]?.label ?? `Unknown(${qtype})`;
        },
        header: "Type",
    },
    {
        accessorKey: "domain",
        header: "Domain",
        enableHiding: false,
    },
    {
        accessorKey: "source",
        filterFn: "equals",
        cell({ cell }) {
            return RESPONSE_SOURCES[(cell.getValue() as string) ?? "unknown"].label;
        },
        header: "Status",
        enableGlobalFilter: false,
    },
    {
        accessorKey: "client",
        header: "Client",
        filterFn: "equalsString",
    },
];

export interface ListEntryRaw {
    id: number;
    timestamp: number;
    label?: string;
    kind: string;
    domain?: string;
    data?: string;
}

export type Domain = Omit<ListEntryRaw, "kind" | "domain" | "data"> & {
    data: string;
    domain: string;
};

export type AdListEntry = Omit<ListEntryRaw, "kind" | "domain" | "data"> & {
    data: string;
};

export const domainColumns: ColumnDef<Domain>[] = [
    {
        accessorKey: "timestamp",
        cell({ cell }) {
            return formatDate(cell.getValue() as number);
        },
        header: "Added At",
        enableGlobalFilter: false,
        enableColumnFilter: false,
    },
    {
        accessorKey: "domain",
        header: "Domain",
        enableColumnFilter: false,
        enableHiding: false,
    },
    {
        accessorKey: "data",
        header: "Address",
        enableHiding: false,
    },
    {
        accessorKey: "label",
        header: "Label",
    },
];

export const adListEntryColumns: ColumnDef<AdListEntry>[] = [
    {
        accessorKey: "timestamp",
        cell({ cell }) {
            return formatDate(cell.getValue() as number);
        },
        header: "Added At",
        enableGlobalFilter: false,
        enableColumnFilter: false,
    },
    {
        accessorKey: "data",
        header: "Block directive",
        enableColumnFilter: false,
        enableHiding: false,
    },
    {
        accessorKey: "label",
        header: "Label",
    },
];

export interface StatsRaw {
    failed_requests_count: number;
    per_source_stats: { [K in "0" | "1" | "2" | "3" | "4"]?: number };
}

export interface Stats {
    uptime_percentage: string;
    total_requests: number;
    blocked_requests: number;
    cached_queries_percentage: string;
}
