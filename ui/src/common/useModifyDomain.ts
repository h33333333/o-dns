import { API_URL } from "@/lib/constants";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";

export const useModifyDomain = () => {
    const queryClient = useQueryClient();

    const { mutate } = useMutation({
        mutationFn: (domain: {
            domain: string;
            ip: string;
            label?: string;
            id?: number;
        }) => {
            let kind: number;
            try {
                z.string().ip({ version: "v4" }).parse(domain.ip);
                kind = 2;
            } catch {
                // IPv6
                kind = 3;
            }

            const entry = {
                // id is present when editing existing domains
                id: domain.id,
                // Protect against empty strings
                label: domain.label ? domain.label : undefined,
                data: domain.ip,
                domain: domain.domain,
                kind,
            };

            return fetch(`${API_URL}/entry`, {
                method: "POST",
                body: JSON.stringify(entry),
                headers: {
                    "Content-Type": "application/json",
                },
            });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["list-entries"] });
        },
    });

    return mutate;
};
