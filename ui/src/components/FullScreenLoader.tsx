import { LoadingSpinner } from "./ui/loader-spinner";

export const FullScreenLoader = () => {
    return (
        <div className="flex flex-col gap-2 justify-center items-center h-full">
            <h1 className="text-lg font-semibold">Fetching data from the DNS server</h1>
            <LoadingSpinner type="long" className="h-8 w-8 animate-spin" />
        </div>
    );
};
