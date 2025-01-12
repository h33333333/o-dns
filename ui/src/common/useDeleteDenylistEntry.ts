import { API_URL } from "@/lib/constants";
import { useMutation, useQueryClient } from "@tanstack/react-query";

export const useDeleteListEntries = () => {
    const queryClient = useQueryClient();

    const { mutate } = useMutation({
        mutationFn: (ids: number[]) => {
            return fetch(`${API_URL}/entry`, {
                method: "DELETE",
                body: JSON.stringify(ids),
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
