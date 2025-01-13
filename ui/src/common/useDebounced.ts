import { SetStateAction, useCallback, useMemo, useState } from "react";

const debounce = (debouncedCall: Function, delay: number) => {
    let timeout: number | null = null;
    return (...args: any[]) => {
        if (timeout !== null) clearTimeout(timeout);
        timeout = setTimeout(debouncedCall, delay, args);
    };
};

const useDebounced = <T>(delay: number, initialValue?: T | (() => T)) => {
    const [state, setState] = useState(initialValue);

    const debounced = useMemo(() => {
        return debounce((value: SetStateAction<T | undefined>) => {
            setState(value);
        }, delay);
    }, [delay]);

    const setStateDebounced = useCallback(
        (value: SetStateAction<T | undefined>) => {
            debounced(value);
        },
        [debounced]
    );

    return { state, setStateDebounced, setState };
};

export default useDebounced;
