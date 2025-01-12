import { useCallback, useState } from "react";
import Button from "../Button";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "../ui/dialog";
import { ChevronFirst, ChevronLast, ChevronLeft, ChevronRight } from "lucide-react";
import { Input } from "../ui/input";

type PaginationControlsProps = {
    totalPages: number;
    currentPage: number;
    isDialogOpen: boolean;
    setIsDialogOpen: (value: boolean) => void;
    setNewPage: (page: number) => void;
    locationText: string;
};

export const PaginationControls = (props: PaginationControlsProps) => {
    const {
        totalPages,
        currentPage,
        isDialogOpen,
        setIsDialogOpen,
        setNewPage,
        locationText,
    } = props;

    const [pageInput, setPageInput] = useState("");
    const pageDialogSubmitCb = useCallback(
        (pageInput: string) => {
            const isValid = pageInput !== "" && !Number.isNaN(+pageInput);
            if (isValid) {
                // Convert to index
                const input = +pageInput - 1;
                // Clamp
                const newIndex = Math.min(Math.max(input, 0), totalPages - 1);
                setNewPage(newIndex);
            }
            setIsDialogOpen(false);
        },
        [setNewPage, setIsDialogOpen]
    );

    return (
        <div className="flex justify-center sm:justify-between items-center">
            <span className="text-muted-foreground hidden sm:block">{locationText}</span>
            <div className="flex justify-end space-x-2">
                <Button
                    variant="outline"
                    size="md"
                    onClick={() => currentPage !== 0 && setNewPage(currentPage - 1)}
                    disabled={currentPage === 0}>
                    <ChevronLeft size={20} />
                </Button>
                <Dialog
                    open={isDialogOpen}
                    onOpenChange={open => {
                        // Clear page input on open
                        if (open) setPageInput("");
                        setIsDialogOpen(open);
                    }}>
                    <DialogTrigger asChild>
                        <Button variant="outline" size="md">
                            <p className="text-nowrap">Go to page</p>
                        </Button>
                    </DialogTrigger>
                    <DialogContent>
                        <DialogHeader>
                            <DialogTitle>
                                {`Currently on page ${currentPage + 1}`}
                            </DialogTitle>
                        </DialogHeader>
                        <DialogDescription asChild>
                            <div className="flex flex-col gap-4">
                                <div className="flex flex-row gap-2 justify-center items-center">
                                    <Button
                                        variant="outline"
                                        size={"sm"}
                                        onClick={() => {
                                            setNewPage(0);
                                            setIsDialogOpen(false);
                                        }}>
                                        <ChevronFirst size={20} />
                                    </Button>
                                    <Input
                                        value={pageInput}
                                        placeholder="Page..."
                                        onFocus={event => (event.target.placeholder = "")}
                                        onBlur={event =>
                                            (event.target.placeholder = "Page...")
                                        }
                                        onChange={event =>
                                            setPageInput(event.target.value)
                                        }
                                        onKeyDown={event => {
                                            if (event.key === "Enter") {
                                                pageDialogSubmitCb(pageInput);
                                            }
                                        }}
                                    />
                                    <Button
                                        variant="outline"
                                        size={"sm"}
                                        onClick={() => {
                                            setNewPage(totalPages - 1);
                                            setIsDialogOpen(false);
                                        }}>
                                        <ChevronLast size={20} />
                                    </Button>
                                </div>
                                <Button
                                    variant="outline"
                                    size="md"
                                    className="whitespace-nowrap shrink-0"
                                    onClick={() => pageDialogSubmitCb(pageInput)}>
                                    Go to page
                                </Button>
                            </div>
                        </DialogDescription>
                    </DialogContent>
                </Dialog>
                <Button
                    variant="outline"
                    size="md"
                    onClick={() =>
                        currentPage !== totalPages - 1 && setNewPage(currentPage + 1)
                    }
                    disabled={currentPage === totalPages - 1}>
                    <ChevronRight size={20} />
                </Button>
            </div>
        </div>
    );
};
