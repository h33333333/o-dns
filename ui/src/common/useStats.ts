import { API_URL } from "@/lib/constants";
import { Stats, StatsRaw } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";

export const useStats = () => {
    const {
        isPending,
        error,
        data: rawData,
    } = useQuery({
        queryKey: ["stats"],
        queryFn: async () =>
            await fetch(`${API_URL}/stats`).then<StatsRaw>(res => res.json()),
        refetchInterval: 1000 * 10,
    });

    const data: Stats | undefined = useMemo(() => {
        if (!rawData) return undefined;

        const stats: Stats = {
            uptime_percentage: "0%",
            total_requests: 0,
            blocked_requests: 0,
            cached_queries_percentage: "0%",
        };

        stats.total_requests = Object.values(rawData.per_source_stats).reduce(
            (acc, stat) => {
                return acc + stat;
            },
            0
        );
        stats.uptime_percentage =
            stats.total_requests === 0
                ? "--"
                : (
                      100 -
                      (rawData.failed_requests_count / stats.total_requests) * 100
                  ).toFixed(2) + "%";

        if (rawData.per_source_stats["0"]) {
            stats.blocked_requests = rawData.per_source_stats["0"];
        }

        if (rawData.per_source_stats["2"]) {
            stats.cached_queries_percentage =
                ((rawData.per_source_stats["2"] / stats.total_requests) * 100).toFixed(
                    2
                ) + "%";
        }

        return stats;
    }, [rawData]);

    return { isPending, error, data };
};
