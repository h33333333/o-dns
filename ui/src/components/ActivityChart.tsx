"use client";

import * as React from "react";
import { Bar, BarChart, CartesianGrid, XAxis } from "recharts";

import {
    ChartConfig,
    ChartContainer,
    ChartTooltip,
    ChartTooltipContent,
} from "@/components/ui/chart";
import Button from "./Button";
import { useMemo } from "react";
import { DashboardCard } from "./DashboardCard";
import { DAY_IN_MILLIS } from "@/lib/constants";
import { getHoursBetweenDates } from "@/lib/utils";
import { useQueryLogs } from "@/common/useQueryLogs";

const chartConfig = {
    total: {
        label: "Total",
        color: "hsl(var(--chart-5))",
    },
    perClient: {
        label: "Per-client",
    },
} satisfies ChartConfig;

export const ActivityChart = () => {
    const [activeChart, setActiveChart] =
        React.useState<keyof typeof chartConfig>("total");

    const { data } = useQueryLogs(
        query => query.timestamp * 1000 >= Date.now() - DAY_IN_MILLIS && !!query.client
    );

    const [chartData, uniqueClients] = useMemo(() => {
        if (!data) return [];

        const now = Date.now();

        const hours = getHoursBetweenDates(now - DAY_IN_MILLIS, now).slice(1);
        const [chartDataRaw, uniqueClients] = data.reduce(
            ([perHourData, uniqueClients], query) => {
                const hour = new Date(query.timestamp * 1000).getHours();

                perHourData[hour].total += 1;
                perHourData[hour][query.client!] ??= 0;
                perHourData[hour][query.client!] += 1;

                uniqueClients.add(query.client!);
                return [perHourData, uniqueClients];
            },
            [
                hours.reduce(
                    (acc, hour) => {
                        acc[hour] = { total: 0 };
                        return acc;
                    },
                    {} as Record<number, { [K in string]: number }>
                ),
                new Set() as Set<string>,
            ]
        );

        const chartData = Object.entries(chartDataRaw)
            .map(
                ([hour, hourData]) =>
                    ({
                        hour,
                        ...hourData,
                    }) as Record<string, any>
            )
            .sort(
                (a, b) => hours.indexOf(Number(a.hour)) - hours.indexOf(Number(b.hour))
            );

        return [chartData, Array.from(uniqueClients)];
    }, [data]);

    const perClientColors = useMemo(
        () =>
            uniqueClients?.map(
                () => "#" + Math.floor(Math.random() * 16777215).toString(16)
            ),
        [uniqueClients]
    );

    if (!data) return null;

    return (
        <DashboardCard
            contentClasses="pb-6 sm:py-6"
            title={"Distribution of requests over the last 24 hours"}
            header={() => {
                return (
                    <div className="flex">
                        {["total", "perClient"].map(key => {
                            const chart = key as keyof typeof chartConfig;
                            return (
                                <Button
                                    key={chart}
                                    disabled={activeChart === chart}
                                    className="h-full text-nowrap flex-1 border-t even:border-l md:border-l md:border-t-0 md:px-12 md:py-6 w-1/2"
                                    variant={"ghost"}
                                    size={"md"}
                                    onClick={() => setActiveChart(chart)}>
                                    {chartConfig[chart].label}
                                </Button>
                            );
                        })}
                    </div>
                );
            }}>
            <ChartContainer
                config={chartConfig}
                className="aspect-auto h-[25svh] h w-full">
                <BarChart
                    accessibilityLayer
                    data={chartData}
                    margin={{
                        left: 12,
                        right: 12,
                    }}>
                    <CartesianGrid vertical={false} />
                    <XAxis
                        dataKey="hour"
                        tickLine={false}
                        axisLine={false}
                        tickMargin={8}
                        minTickGap={32}
                        tickFormatter={value => {
                            return `${value.length === 1 ? "0" + value : value}:00`;
                        }}
                    />
                    <ChartTooltip
                        content={
                            <ChartTooltipContent
                                className="w-[150px]"
                                labelFormatter={value => {
                                    return `${value.length === 1 ? "0" + value : value}:00`;
                                }}
                            />
                        }
                    />
                    {activeChart === "total" && (
                        <Bar
                            dataKey={activeChart}
                            fill={`var(--color-${activeChart})`}
                            radius={[4, 4, 0, 0]}
                        />
                    )}
                    {activeChart === "perClient" &&
                        uniqueClients!.map((client, idx) => {
                            return (
                                <Bar
                                    key={client}
                                    dataKey={client}
                                    stackId="a"
                                    fill={perClientColors![idx]}
                                    radius={
                                        idx === 0
                                            ? [0, 0, 4, 4]
                                            : idx === uniqueClients!.length - 1
                                              ? [4, 4, 0, 0]
                                              : undefined
                                    }
                                />
                            );
                        })}
                </BarChart>
            </ChartContainer>
        </DashboardCard>
    );
};
