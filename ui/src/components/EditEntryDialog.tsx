import { ReactNode } from "react";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from "./ui/dialog";
import {
    Form,
    FormControl,
    FormDescription,
    FormField,
    FormItem,
    FormLabel,
    FormMessage,
} from "./ui/form";
import { FieldValues, Path, SubmitHandler, UseFormReturn } from "react-hook-form";
import Button from "./Button";
import { Input } from "./ui/input";

type FieldConfig = {
    label: string;
    placeholder?: string;
    description?: string;
};

type EditEntryDialogProps<F extends FieldValues> = {
    isOpen: boolean;
    onOpenChange?: (open: boolean) => void;
    title: string;
    form: UseFormReturn<F>;
    onFormSubmit: SubmitHandler<F>;
    fieldConfigs: {
        [T in Path<F>]: FieldConfig;
    };
};

export const EditEntryDialog = <F extends FieldValues>(
    props: EditEntryDialogProps<F>
): ReactNode => {
    const { isOpen, onOpenChange, title, form, onFormSubmit, fieldConfigs } = props;

    return (
        <Dialog open={isOpen} onOpenChange={onOpenChange}>
            <DialogContent>
                {title && (
                    <DialogHeader>
                        <DialogTitle>{title}</DialogTitle>
                    </DialogHeader>
                )}
                <DialogDescription asChild>
                    <Form {...form}>
                        <form
                            onSubmit={form.handleSubmit(onFormSubmit)}
                            className="flex flex-col gap-4">
                            {Object.entries<FieldConfig>(fieldConfigs).map(
                                ([field, config]) => {
                                    return (
                                        <FormField
                                            key={field}
                                            control={form.control}
                                            name={field as Path<F>}
                                            render={({ field }) => (
                                                <FormItem>
                                                    <FormLabel>{config.label}</FormLabel>
                                                    <FormControl>
                                                        <Input
                                                            placeholder={
                                                                config.placeholder
                                                            }
                                                            {...field}
                                                        />
                                                    </FormControl>
                                                    {config.description && (
                                                        <FormDescription>
                                                            {config.description}
                                                        </FormDescription>
                                                    )}
                                                    <FormMessage />
                                                </FormItem>
                                            )}
                                        />
                                    );
                                }
                            )}
                            <Button
                                type="submit"
                                variant="outline"
                                size="md"
                                className="ml-auto mt-0">
                                Submit
                            </Button>
                        </form>
                    </Form>
                </DialogDescription>
            </DialogContent>
        </Dialog>
    );
};
