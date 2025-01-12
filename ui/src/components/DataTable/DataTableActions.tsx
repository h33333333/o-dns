import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "../ui/dropdown-menu";
import Button from "../Button";
import { Ellipsis } from "lucide-react";
import { Row } from "@tanstack/react-table";

export const DataTableActions = <T,>({
    actions,
    row,
}: {
    actions: {
        label: string;
        callback: (row: Row<T>) => void;
    }[];
    row: Row<T>;
}) => {
    return (
        <div onClick={event => event.stopPropagation()}>
            <DropdownMenu>
                <DropdownMenuTrigger asChild>
                    <Button size={"sm"} variant={"ghost"} className="rounded-lg">
                        <Ellipsis size={20} />
                    </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                    {actions.map(({ label, callback }, idx) => (
                        <DropdownMenuItem
                            key={idx}
                            onSelect={event => {
                                event.stopPropagation();
                                callback(row);
                            }}>
                            {label}
                        </DropdownMenuItem>
                    ))}
                </DropdownMenuContent>
            </DropdownMenu>
        </div>
    );
};
