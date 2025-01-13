import { API_URL } from "@/lib/constants";
import { Query } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";

export const useQueryLogs = (filterFn?: (query: Query) => boolean) => {
    const {
        isPending,
        error,
        data: rawData,
    } = useQuery({
        queryKey: ["query-logs"],
        queryFn: async () =>
            await fetch(`${API_URL}/logs`).then<Query[]>(res => res.json()),
        refetchInterval: 1000 * 10,
    });

    const data = useMemo(() => {
        return filterFn ? rawData?.filter(filterFn) : rawData;
    }, [rawData]);

    return { isPending, error, data };
};
