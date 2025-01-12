import { API_URL } from "@/lib/constants";
import { DOMAIN_REGEXP } from "@/lib/utils";
import { useMutation, useQueryClient } from "@tanstack/react-query";

export const useModifyDenyListEntry = () => {
    const queryClient = useQueryClient();

    const { mutate } = useMutation({
        mutationFn: (modifiedEntry: {
            blockDirective: string;
            label?: string;
            id?: number;
        }) => {
            const entry = {
                // id is present when editing existing entries
                id: modifiedEntry.id,
                // Protect against empty strings
                label: modifiedEntry.label ? modifiedEntry.label : undefined,
                ...(DOMAIN_REGEXP.test(modifiedEntry.blockDirective)
                    ? {
                          kind: 0,
                          domain: modifiedEntry.blockDirective,
                      }
                    : { kind: 1, data: modifiedEntry.blockDirective }),
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
