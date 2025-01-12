import { BarChart, LayoutList, ShieldBan, ScrollText } from "lucide-react";
import { useState } from "react";
import { NavLink } from "react-router";

const navItems = [
    {
        icon: BarChart,
        label: "Dashboard",
        href: "/",
    },
    {
        icon: ScrollText,
        label: "Query log",
        href: "/log",
    },
    {
        icon: LayoutList,
        label: "Hosts",
        href: "/hosts",
    },
    {
        icon: ShieldBan,
        label: "Denylist",
        href: "/denylist",
    },
];

const NavBar = () => {
    const [isCollapsed, setIsCollapsed] = useState(true);

    return (
        <nav
            className={`flex flex-col shrink-0 bg-gray-800 text-white transition-all duration-300 ${isCollapsed ? "basis-[60px]" : "sm:basis-56"}`}>
            <div
                className={`p-1 flex items-center justify-between border-b box-border border-gray-700 ${isCollapsed ? "" : "basis-[52px]"}`}>
                <div
                    className={`flex-1 justify-center ${isCollapsed ? "sm:min-w-0" : ""}`}>
                    <NavLink
                        to={"/"}
                        className={() =>
                            `font-bold text-xl absolute top-4 left-5 transition-all duration-200 block whitespace-nowrap ${isCollapsed ? "sm:opacity-0 sm:translate-x-8 sm:pointer-events-none" : "sm:opacity-100 sm:translate-x-0"}`
                        }>
                        Oxidized DNS
                    </NavLink>
                </div>
                <button
                    onClick={() => setIsCollapsed(!isCollapsed)}
                    className={`p-4 rounded-lg hover:bg-gray-700 transition-all`}>
                    {/* Hamburger menu  */}
                    <div className="relative m-[1px] h-[18px] w-[18px] *:rounded-sm">
                        <span
                            className={`absolute top-1/2 bottom-0 block h-0.5 w-[18px] bg-white transition-all duration-300 ease-in-out ${!isCollapsed ? "sm:w-2 -rotate-45 -translate-y-[1px] sm:-translate-x-[1.5px] sm:-translate-y-[3px]" : "-translate-y-[7px]"}`}
                        />
                        <span
                            className={`absolute top-1/2 bottom-0 h-0.5 w-[18px] block bg-white transition-all duration-300 ease-in-out ${!isCollapsed ? "-translate-x-4 opacity-0 sm:opacity-100 sm:translate-x-0 -translate-y-[1px]" : "-translate-y-[1px]"}`}
                        />
                        <span
                            className={`absolute top-1/2 bottom-0 block h-0.5 w-[18px] bg-white transition-all duration-300 ease-in-out ${!isCollapsed ? "sm:w-2 rotate-45 -translate-y-[1px] sm:-translate-x-[1.5px] sm:translate-y-[1.5px]" : "translate-y-[5px]"}`}
                        />
                    </div>
                </button>
            </div>

            <div
                className={`absolute w-full transition-all duration-300 bg-gray-800 top-[61px] sm:static z-50 overflow-hidden ${isCollapsed ? "max-h-0 sm:max-h-fit" : "max-h-96"}`}>
                <ul
                    className={`p-1 flex flex-col sm:pointer-events-auto ${isCollapsed ? "pointer-events-none" : ""}`}>
                    {navItems.map((item, index) => (
                        <li key={index}>
                            <NavLink
                                to={item.href}
                                className={({ isActive }) =>
                                    `flex items-center p-4 hover:bg-gray-700 rounded-lg transition-colors ${isActive ? "" : "text-gray-500"}`
                                }>
                                <item.icon
                                    size={20}
                                    className="shrink-0 transition-colors duration-200"
                                />
                                <span
                                    className={`transition-all duration-300 absolute left-14 overflow-hidden ${isCollapsed ? "opacity-0 -translate-x-3 max-w-0" : "opacity-100 translate-x-0 max-w-96"}`}>
                                    {item.label}
                                </span>
                            </NavLink>
                        </li>
                    ))}
                </ul>
            </div>
        </nav>
    );
};

export default NavBar;
