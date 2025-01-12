import { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { cn } from "@/lib/utils";

export type DashboardCardProps = {
    title?: string;
    header?: () => ReactNode;
    containerClasses?: string;
    contentClasses?: string;
    children?: ReactNode;
};

export const DashboardCard = ({
    title,
    header,
    containerClasses,
    contentClasses,
    children,
}: DashboardCardProps) => {
    return (
        <Card className={containerClasses}>
            {(title || header) && (
                <CardHeader className="flex flex-col space-y-0 border-b p-0 md:flex-row">
                    {title && (
                        <CardTitle className="flex flex-1 justify-center items-center md:justify-start gap-1 px-6 py-5 md:py-6 md:w-4/5">
                            {title}
                        </CardTitle>
                    )}
                    {header && header()}
                </CardHeader>
            )}
            {children && (
                <CardContent className={cn("px-2 py-0 sm:p-6", contentClasses)}>
                    {children}
                </CardContent>
            )}
        </Card>
    );
};
