import { useCallback, useEffect, useState } from "react";
import { adListEntryColumns } from "@/lib/types";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { DOMAIN_REGEXP } from "@/lib/utils";
import { EditEntryDialog } from "./EditEntryDialog";
import DataTable from "./DataTable";
import { useListEntries } from "@/common/useListEntries";
import { useModifyDenyListEntry } from "@/common/useModifyDenylistEntry";
import { useDeleteListEntries } from "@/common/useDeleteDenylistEntry";
import { FullScreenLoader } from "./FullScreenLoader";

const formSchema = z.object({
    blockDirective: z.custom<string>(
        val => {
            if (!val) return false;
            if (!z.string().regex(DOMAIN_REGEXP).safeParse(val).success) {
                try {
                    new RegExp(val);
                } catch {
                    return false;
                }
            }
            return true;
        },
        { message: "Not a valid domain/RegExp" }
    ),
    label: z.string().optional(),
});

export const Denylist = () => {
    const [, , [, data]] = useListEntries();
    const modifyEntry = useModifyDenyListEntry();
    const deleteListEntries = useDeleteListEntries();

    const [editBlockEntryDialogOpen, setEditBlockEntryDialogOpen] = useState(false);

    const [selectedItem, setSelectedItem] = useState<
        z.infer<typeof formSchema> & { id: number }
    >();

    const form = useForm<z.infer<typeof formSchema>>({
        resolver: zodResolver(formSchema),
        defaultValues: {
            blockDirective: "",
            label: "",
        },
        values: selectedItem,
    });

    useEffect(() => {
        if (form.formState.isSubmitSuccessful) {
            setSelectedItem(undefined);
            form.reset();
        }
    }, [form.formState, form.reset]);

    const onEditEntrySubmit = useCallback(
        (
            values: z.infer<typeof formSchema>,
            selectedItem?: z.infer<typeof formSchema> & { id: number }
        ) => {
            // This handles both edits and new entries
            if (
                !selectedItem ||
                values.blockDirective !== selectedItem?.blockDirective ||
                values.label !== selectedItem.label
            ) {
                modifyEntry({ ...values, id: selectedItem?.id });
            }
            setEditBlockEntryDialogOpen(false);
        },
        [setEditBlockEntryDialogOpen]
    );

    return data ? (
        <>
            <DataTable
                columns={adListEntryColumns}
                data={data}
                defaultPageSize={15}
                pageSizes={[15, 20, 50, 100]}
                enableSorting
                showPaginationControls
                showColumnVisibilityControls
                enableFuzzySearch
                enableColumnFiltering
                addEntryCallback={() => setEditBlockEntryDialogOpen(true)}
                deleteSelectedRowsCallback={selected => {
                    deleteListEntries(selected.map(row => row.original.id));
                }}
                rowActions={[
                    {
                        label: "Edit",
                        callback: row => {
                            setSelectedItem({
                                id: row.original.id,
                                blockDirective: row.original.data,
                                label: row.original.label ?? "",
                            });
                            setEditBlockEntryDialogOpen(true);
                        },
                    },
                    {
                        label: "Delete",
                        callback: row => {
                            deleteListEntries([row.original.id]);
                        },
                    },
                ]}
                tableContainerClasses="rounded-md border"
            />
            <EditEntryDialog
                title="Block a domain"
                isOpen={editBlockEntryDialogOpen}
                onOpenChange={open => {
                    if (!open) {
                        setSelectedItem(undefined);
                        form.reset();
                    }
                    setEditBlockEntryDialogOpen(open);
                }}
                form={form}
                onFormSubmit={values => onEditEntrySubmit(values, selectedItem)}
                fieldConfigs={{
                    blockDirective: {
                        label: "Block Directive",
                        description: "A valid domain/RegExp",
                        placeholder: ".*\\.ru$",
                    },
                    label: {
                        label: "Label",
                        description: "Optional label",
                        placeholder: "All russian domains",
                    },
                }}
            />
        </>
    ) : (
        <FullScreenLoader />
    );
};
