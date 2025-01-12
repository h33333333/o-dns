import { forwardRef } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonStyles = cva(
    "inline-flex items-center justify-center font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
    {
        variants: {
            variant: {
                primary: "bg-blue-600 text-white hover:bg-blue-700",
                secondary: "bg-gray-200 text-gray-900 hover:bg-gray-300",
                ghost: "hover:bg-gray-100 text-gray-900",
                outline:
                    "border rounded-md border-gray-200 text-gray-900 hover:bg-gray-100",
            },
            size: {
                sm: "h-9 px-3 py-2 text-sm",
                md: "h-10 px-6 py-4 text-base",
                lg: "h-12 px-12 py-6 text-lg",
            },
            disabled: {
                true: "disabled:pointer-events-none",
            },
        },
        compoundVariants: [
            {
                variant: "primary",
                disabled: true,
                class: "bg-blue-400",
            },
            {
                variant: "secondary",
                disabled: true,
                class: "bg-gray-100",
            },
            {
                variant: "ghost",
                disabled: true,
                class: "bg-gray-100",
            },
            {
                variant: "outline",
                disabled: true,
                class: "text-muted-foreground",
            },
        ],
        defaultVariants: {
            variant: "primary",
            size: "md",
            disabled: false,
        },
    }
);

type ButtonVariantProps = VariantProps<typeof buttonStyles>;

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> &
    Omit<ButtonVariantProps, "disabled">;

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
    ({ children, className, variant, size, ...props }, ref) => {
        return (
            <button
                className={cn(
                    buttonStyles({ variant, size, disabled: props.disabled }),
                    className
                )}
                ref={ref}
                {...props}>
                {children}
            </button>
        );
    }
);

export default Button;
