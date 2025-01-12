import { RouteOff } from "lucide-react";

export const ErrorPage = () => {
    return (
        <div className="flex items-center flex-1 flex-col px-6 py-24 gap-6">
            <h1 className="text-xl">
                It seems that you've wandered off. This page is still in development :)
            </h1>
            <RouteOff size={50} />
        </div>
    );
};
