import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export const DOMAIN_REGEXP =
    /^(?:\*\.)?(?:(?<=\*\.)|(?<!\*\.)(?:[a-zA-Z0-9][A-Za-z0-9-]{0,61}[a-zA-Z0-9]\.)+)[A-Za-z]{2,63}$/;

export function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs));
}

export const formatDate = (timestamp: number): string => {
    const date = new Date(timestamp);
    return `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
};

export const getHoursBetweenDates = (start: number, end: number): number[] => {
    if (start > end) {
        throw new Error("Start date must be before end date");
    }

    let current = new Date(start);
    current.setMinutes(0, 0, 0);

    const hours = [];
    while (current.getTime() <= end) {
        hours.push(current.getHours());

        current = new Date(current.getTime() + 60 * 60 * 1000);
    }

    return hours;
};
