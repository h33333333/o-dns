import {
    Select,
    SelectContent,
    SelectGroup,
    SelectItem,
    SelectLabel,
    SelectTrigger,
    SelectValue,
} from "../ui/select";

type PaginationSelectorProps = {
    currentPageSize: number;
    pageSizes: number[];
    setter: (pageSize: number) => void;
};

export const PaginationSelector = (props: PaginationSelectorProps) => {
    const { pageSizes, currentPageSize, setter } = props;

    return (
        <div className="flex gap-6 items-center">
            <Select
                value={currentPageSize.toString()}
                onValueChange={value => setter(Number(value))}>
                <SelectTrigger className="w-[70px]">
                    <SelectValue placeholder="Page size" />
                </SelectTrigger>
                <SelectContent className="w-[70px]">
                    <SelectGroup>
                        <SelectLabel>Page Size</SelectLabel>
                        {pageSizes.map(size => (
                            <SelectItem key={size} value={size.toString()}>
                                {size}
                            </SelectItem>
                        ))}
                    </SelectGroup>
                </SelectContent>
            </Select>
        </div>
    );
};
