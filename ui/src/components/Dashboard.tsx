import { ActivityChart } from "./ActivityChart";
import { QueryChart } from "./QueryChart";
import { queryColumns } from "@/lib/types";
import { DashboardCard } from "./DashboardCard";
import DataTable from "./DataTable";
import { useQueryLogs } from "@/common/useQueryLogs";
import { StatsDashboard } from "./StatsDashboard";
import { Skeleton } from "./ui/skeleton";

const Dashboard = () => {
    const [, , data] = useQueryLogs();

    return data ? (
        <div className="flex flex-col gap-4">
            <div className="flex flex-col 2xl:flex-row gap-4 justify-between w-full">
                <DashboardCard
                    containerClasses="w-full"
                    title="Latest queries"
                    contentClasses="pb-6 sm:pt-0">
                    <DataTable
                        columns={queryColumns}
                        data={data}
                        defaultPageSize={7}
                        fullWidth
                    />
                </DashboardCard>
                <QueryChart />
            </div>
            <ActivityChart />
            <DashboardCard
                title="All-time stats"
                containerClasses="w-full"
                contentClasses="flex flex-col md:flex-row gap-8 w-full items-center justify-between py-6">
                <StatsDashboard />
            </DashboardCard>
        </div>
    ) : (
        <DashboardSkeleton />
    );
};

const DashboardSkeleton = () => {
    return (
        <div className="flex flex-col gap-4">
            <div className="flex flex-col 2xl:flex-row gap-4 justify-between w-full">
                <Skeleton className="rounded-xl w-full h-[589px] md:h-[477px] 2xl:h-[497px]" />
                <Skeleton className="rounded-xl w-full h-[490px] md:h-[471px] 2xl:w-1/3 2xl:h-[497px]" />
            </div>
            <Skeleton className="rounded-xl w-full h-[298px] 2xl:h-[281px]" />
            <Skeleton className="rounded-xl w-full h-[298px] md:h-[161px] 2xl:h-[281px]" />
        </div>
    );
};

export default Dashboard;
