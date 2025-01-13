import { useStats } from "@/common/useStats";
import { Stats } from "@/lib/types";
import { Activity, ShieldAlert, DatabaseZap, Search } from "lucide-react";

const statsConfig: Record<
    keyof Stats,
    { icon: React.ComponentType<any>; label: string }
> = {
    total_requests: { icon: Search, label: "Total Requests" },
    blocked_requests: { icon: ShieldAlert, label: "Blocked" },
    cached_queries_percentage: { icon: DatabaseZap, label: "Cached" },
    uptime_percentage: { icon: Activity, label: "Uptime" },
};

export const StatsDashboard = () => {
    const { data } = useStats();

    if (!data) return null;

    return (
        <>
            {Object.entries(data).map(([key, stat]) => {
                const config = statsConfig[key as keyof Stats];
                return (
                    <div
                        className="flex justify-stretch items-center gap-4 w-36"
                        key={key}>
                        <config.icon className="h-5 aspect-square text-blue-600" />
                        <div className="flex flex-col justify-center">
                            <p className="text-sm text-gray-500">{config.label}</p>
                            <p className="text-lg font-bold">{stat}</p>
                        </div>
                    </div>
                );
            })}
        </>
    );
};
