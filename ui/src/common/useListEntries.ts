import { API_URL } from "@/lib/constants";
import { AdListEntry, Domain, ListEntryRaw } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";

export const useListEntries = () => {
    const {
        isPending,
        error,
        data: rawData,
    } = useQuery({
        queryKey: ["list-entries"],
        queryFn: async () =>
            await fetch(`${API_URL}/entry`).then<ListEntryRaw[]>(res => res.json()),
        refetchInterval: 1000 * 60 * 5,
    });

    const data = useMemo(() => {
        const domains: Domain[] = [];
        const adListEntries: AdListEntry[] = [];

        if (!rawData) return [undefined, undefined] as const;

        return rawData?.reduce(
            ([domains, adListEntries], listEntry) => {
                const common = {
                    id: listEntry.id,
                    label: listEntry.label,
                    timestamp: listEntry.timestamp * 1000,
                };
                if (["AllowA", "AllowAAAA"].includes(listEntry.kind)) {
                    // This is a domain entry
                    domains.push({
                        ...common,
                        domain: listEntry.domain!,
                        data: listEntry.data!,
                    });
                } else {
                    // This is an AdList entry
                    adListEntries.push({
                        ...common,
                        data:
                            listEntry.kind === "Deny"
                                ? listEntry.domain!
                                : listEntry.data!,
                    });
                }

                return [domains, adListEntries] as const;
            },
            [domains, adListEntries] as const
        );
    }, [rawData]);

    return [isPending, error, data] as const;
};
