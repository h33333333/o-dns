import { useCallback, useEffect, useState } from "react";
import { domainColumns } from "@/lib/types";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { DOMAIN_REGEXP } from "@/lib/utils";
import { EditEntryDialog } from "./EditEntryDialog";
import DataTable from "./DataTable";
import { useListEntries } from "@/common/useListEntries";
import { useDeleteListEntries } from "@/common/useDeleteDenylistEntry";
import { useModifyDomain } from "@/common/useModifyDomain";
import { FullScreenLoader } from "./FullScreenLoader";

const formSchema = z.object({
    domain: z.string().regex(DOMAIN_REGEXP, "Invalid domain"),
    ip: z.string().ip(),
    label: z.string().optional(),
});

const fieldConfigs = {
    domain: {
        label: "Domain",
        description: "Domain that you want to add to the hosts file",
        placeholder: "example.com",
    },
    ip: {
        label: "IP",
        description: "IP address that you want to associate this domain with",
        placeholder: "127.0.0.1",
    },
    label: {
        label: "Label",
        description: "Optional label",
        placeholder: "An example domain",
    },
};

export const Hosts = () => {
    const [, , [data]] = useListEntries();
    const modifyDomain = useModifyDomain();
    const deleteListEntries = useDeleteListEntries();

    const [editDomainDialogOpen, setEditDomainDialogOpen] = useState(false);

    const [selectedItem, setSelectedItem] = useState<
        z.infer<typeof formSchema> & { id: number }
    >();

    const form = useForm<z.infer<typeof formSchema>>({
        resolver: zodResolver(formSchema),
        defaultValues: {
            domain: "",
            ip: "",
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
                values.domain !== selectedItem?.domain ||
                values.ip !== selectedItem.ip ||
                values.label !== selectedItem.label
            ) {
                modifyDomain({ ...values, id: selectedItem?.id });
            }
            setEditDomainDialogOpen(false);
        },
        [setEditDomainDialogOpen]
    );

    return data ? (
        <>
            <DataTable
                columns={domainColumns}
                data={data}
                defaultPageSize={15}
                pageSizes={[15, 20, 50, 100]}
                enableSorting
                showPaginationControls
                showColumnVisibilityControls
                enableFuzzySearch
                enableColumnFiltering
                addEntryCallback={() => setEditDomainDialogOpen(true)}
                deleteSelectedRowsCallback={selected => {
                    deleteListEntries(selected.map(row => row.original.id));
                }}
                rowActions={[
                    {
                        label: "Edit",
                        callback: row => {
                            setSelectedItem({
                                id: row.original.id,
                                domain: row.original.domain,
                                ip: row.original.data,
                                label: row.original.label ?? "",
                            });
                            setEditDomainDialogOpen(true);
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
                title="Add new known domain"
                isOpen={editDomainDialogOpen}
                onOpenChange={open => {
                    if (!open) {
                        setSelectedItem(undefined);
                        form.reset();
                    }
                    setEditDomainDialogOpen(open);
                }}
                form={form}
                onFormSubmit={values => onEditEntrySubmit(values, selectedItem)}
                fieldConfigs={fieldConfigs}
            />
        </>
    ) : (
        <FullScreenLoader />
    );
};
