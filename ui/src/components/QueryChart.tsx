import { Label, Pie, PieChart } from "recharts";
import {
    ChartContainer,
    ChartLegend,
    ChartLegendContent,
    ChartTooltip,
    ChartTooltipContent,
} from "@/components/ui/chart";
import Button from "./Button";
import { useMemo, useState } from "react";
import { DashboardCard } from "./DashboardCard";
import { DAY_IN_MILLIS, DNS_QUERY_TYPES, RESPONSE_SOURCES } from "@/lib/constants";
import { useQueryLogs } from "@/common/useQueryLogs";

const viewConfigs = {
    type: {
        label: "Query Type",
    },
    status: {
        label: "Status",
    },
};

export const QueryChart = () => {
    const [activeView, setActiveView] = useState<keyof typeof viewConfigs>("type");

    const { data } = useQueryLogs(
        query => query.timestamp * 1000 >= Date.now() - DAY_IN_MILLIS
    );

    const [dataByQueryType, dataByQueryStatus] = useMemo(() => {
        if (!data) return [];

        const [byQtype, byStatus] = data.reduce(
            ([byQtype, byStatus], query) => {
                byQtype[query.qtype.toString()] ??= 0;
                byQtype[query.qtype.toString()] += 1;

                const status = query.source?.toString() ?? "unknown";
                byStatus[status] ??= 0;
                byStatus[status] += 1;

                return [byQtype, byStatus];
            },
            [{}, {}] as [{ [K in string]: number }, { [K in string]: number }]
        );

        return [
            Object.entries(byQtype).map(([qtype, total]) => {
                return {
                    type: qtype,
                    total,
                    fill: "#" + Math.floor(Math.random() * 16777215).toString(16),
                };
            }),
            Object.entries(byStatus).map(([status, total]) => {
                return {
                    status,
                    total,
                    fill: "#" + Math.floor(Math.random() * 16777215).toString(16),
                };
            }),
        ];
    }, [data]);

    if (!data) return null;

    return (
        <DashboardCard
            containerClasses="w-full 2xl:w-1/3"
            contentClasses="py-3"
            title="Last 24 hours queries"
            header={() => (
                <div className="flex">
                    {(["type", "status"] as (keyof typeof viewConfigs)[]).map(view => {
                        const config = viewConfigs[view];
                        return (
                            <Button
                                key={view}
                                disabled={activeView === view}
                                className="h-full text-nowrap flex-1 border-t even:border-l md:border-l md:border-t-0 md:px-12 md:py-6 w-1/2"
                                variant={"ghost"}
                                size={"md"}
                                onClick={() => setActiveView(view)}>
                                {config.label}
                            </Button>
                        );
                    })}
                </div>
            )}>
            <ChartContainer
                config={activeView === "type" ? DNS_QUERY_TYPES : RESPONSE_SOURCES}
                className="flex flex-grow aspect-square mx-auto max-h-[350px]">
                <PieChart>
                    <ChartTooltip
                        cursor={false}
                        content={<ChartTooltipContent hideLabel />}
                    />
                    <Pie
                        data={activeView === "type" ? dataByQueryType : dataByQueryStatus}
                        animationBegin={100}
                        dataKey="total"
                        nameKey={activeView}
                        innerRadius={55}
                        strokeWidth={5}>
                        <Label
                            content={({ viewBox }) => {
                                if (viewBox && "cx" in viewBox && "cy" in viewBox) {
                                    return (
                                        <text
                                            x={viewBox.cx}
                                            y={viewBox.cy}
                                            textAnchor="middle"
                                            dominantBaseline="middle">
                                            <tspan
                                                x={viewBox.cx}
                                                y={viewBox.cy}
                                                className="fill-foreground text-3xl font-bold">
                                                {data.length}
                                            </tspan>
                                            <tspan
                                                x={viewBox.cx}
                                                y={(viewBox.cy || 0) + 24}
                                                className="fill-muted-foreground">
                                                Queries
                                            </tspan>
                                        </text>
                                    );
                                }
                            }}
                        />
                    </Pie>
                    <ChartLegend
                        content={<ChartLegendContent />}
                        className="-translate-y-2 flex-wrap gap-2 [&>*]:basis-1/4 [&>*]:justify-center"
                    />
                </PieChart>
            </ChartContainer>
        </DashboardCard>
    );
};
