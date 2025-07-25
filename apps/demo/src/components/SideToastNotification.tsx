import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CheckIcon, PlusIcon, Trash2Icon, MinusIcon } from "lucide-react";

function TwitterBlueCheckIcon({ size = 18, className = "" }) {
    return (
        <svg
            width={size}
            height={size}
            viewBox="0 0 24 24"
            fill="none"
            className={className}
            style={{ display: "inline-block", verticalAlign: "middle" }}
        >
            <circle cx="12" cy="12" r="12" fill="#1D9BF0" />
            <path
                d="M12 6.5l1.176 3.62h3.806l-3.08 2.238 1.176 3.62L12 13.74l-3.078 2.238 1.176-3.62-3.08-2.238h3.806L12 6.5z"
                fill="#fff"
            />
        </svg>
    );
}

interface SideToastNotificationsProps {
    notifications: {
        id: string;
        sender: string;
        message: string;
        verified: boolean;
        onAccept: (msg: string) => void;
        onReject: () => void;
    }[];
    removeNotification: (id: string) => void;
}

export function SideToastNotifications({
    notifications,
    removeNotification,
}: SideToastNotificationsProps) {
    const [shrunk, setShrunk] = useState<{ [id: string]: boolean }>({});
    const [expanded, setExpanded] = useState<{ [id: string]: boolean }>({});
    const [isAnyHovered, setIsAnyHovered] = useState(false);

    let hoverTimeout: ReturnType<typeof setTimeout> | null = null;

    // Notifications always arrive collapsed
    useEffect(() => {
        setShrunk((prev) => {
            const updated = { ...prev };

            notifications.forEach((notif) => {
                if (!(notif.id in updated)) {
                    updated[notif.id] = true; // collapsed by default
                }
            });

            // Remove state for old notifications
            Object.keys(updated).forEach((id) => {
                if (!notifications.find((n) => n.id === id)) {
                    delete updated[id];
                }
            });

            return updated;
        });

        setExpanded((prev) => {
            const updated = { ...prev };
            Object.keys(updated).forEach((id) => {
                if (!notifications.find((n) => n.id === id)) {
                    delete updated[id];
                }
            });
            return updated;
        });
    }, [notifications]);

    const handleExpand = (id: string) => {
        setExpanded((prev) => ({ ...prev, [id]: true }));
    };

    const handleShrink = (id: string) => {
        setExpanded((prev) => ({ ...prev, [id]: false }));
    };

    const handleMouseEnter = () => {
        if (hoverTimeout) clearTimeout(hoverTimeout);
        setIsAnyHovered(true);
    };

    const handleMouseLeave = () => {
        hoverTimeout = setTimeout(() => setIsAnyHovered(false), 80);
    };

    const compressStack = !isAnyHovered && notifications.length > 1;
    const overlapOffset = compressStack ? "-28px" : "16px"; // negative margin to compress stack

    return (
        <div
            className="fixed left-1/2 z-[9999] w-full flex flex-col items-center pointer-events-none"
            style={{ top: "5px", transform: "translateX(-50%)" }}
        >
            <div
                className="flex flex-col items-center pointer-events-auto w-fit mx-auto"
                onMouseEnter={handleMouseEnter}
                onMouseLeave={handleMouseLeave}
                style={{ paddingTop: "16px", paddingBottom: "16px" }}
            >
                <AnimatePresence>
                    {notifications.map((notif, idx) => {
                        const isShrunk = shrunk[notif.id] && !expanded[notif.id];
                        const zIndex = isAnyHovered ? 100 + idx : 10 + idx;

                        return (
                            <motion.div
                                key={notif.id}
                                initial={{ y: -80, opacity: 0 }}
                                animate={{ y: 0, opacity: 1 }}
                                exit={{ y: -80, opacity: 0 }}
                                transition={{ type: "spring", stiffness: 400, damping: 30 }}
                                className={
                                    (isShrunk
                                        ? "bg-blue-900/95 border border-blue-700 shadow-xl rounded-lg px-4 py-1 flex items-center min-w-[220px] max-w-full h-[36px] overflow-hidden pointer-events-auto"
                                        : "bg-blue-900/95 border border-blue-700 shadow-xl rounded-lg p-4 flex flex-col min-w-[320px] max-w-full pointer-events-auto") +
                                    (compressStack ? " compress-toast" : " gap-4")
                                }
                                style={{
                                    minHeight: isShrunk ? 36 : undefined,
                                    maxHeight: isShrunk ? 36 : undefined,
                                    marginTop: idx !== 0 ? overlapOffset : 0,
                                    zIndex,
                                    transition: "all 0.4s cubic-bezier(.4,2,.6,1)",
                                }}
                            >
                                {isShrunk ? (
                                    <div className="flex justify-between items-center w-full">
                                        <span className="font-medium truncate">
                                            Request from {notif.sender.slice(0, 8)}...{notif.sender.slice(-8)}
                                        </span>
                                        <button
                                            className="text-gray-400 hover:text-white ml-2"
                                            onClick={() => handleExpand(notif.id)}
                                            aria-label="Expand"
                                        >
                                            <PlusIcon size={18} />
                                        </button>
                                    </div>
                                ) : (
                                    <>
                                        <div className="flex justify-between items-start">
                                            <div>
                                                <div className="flex items-center gap-2 mb-1">
                                                    <span className="font-medium">
                                                        Request from{" "}
                                                        <a
                                                            href={`https://basescan.org/address/${notif.sender}`}
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                            className="underline decoration-dotted underline-offset-2 hover:text-blue-200 transition"
                                                        >
                                                            {notif.sender.slice(0, 8)}...{notif.sender.slice(-8)}
                                                        </a>
                                                    </span>
                                                    {notif.verified ? (
                                                        <span className="relative group flex items-center">
                                                            <TwitterBlueCheckIcon size={18} />
                                                            <span
                                                                className="absolute left-1/2 -top-8 -translate-x-1/2 px-2 py-1 bg-blue-900 text-blue-200 text-xs rounded shadow opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity duration-200 whitespace-nowrap"
                                                                style={{ zIndex: 100 }}
                                                            >
                                                                Verified user
                                                            </span>
                                                        </span>
                                                    ) : (
                                                        <span className="text-xs text-yellow-400 flex items-center gap-1">
                                                            <span className="text-lg">⚠️</span> Unverified
                                                        </span>
                                                    )}
                                                </div>
                                                <p className="text-sm text-gray-200 mb-2">"{notif.message}"</p>
                                            </div>
                                            {shrunk[notif.id] && expanded[notif.id] && (
                                                <button
                                                    className="ml-3 text-gray-400 hover:text-white"
                                                    onClick={() => handleShrink(notif.id)}
                                                    aria-label="Collapse"
                                                >
                                                    <MinusIcon size={18} />
                                                </button>
                                            )}
                                        </div>
                                        <div className="flex gap-2 mt-2">
                                            <input
                                                type="text"
                                                placeholder="Add a note"
                                                className="flex-1 px-3 py-1 bg-gray-800 border border-gray-600 rounded text-sm"
                                                id={`side-toast-response-${notif.id}`}
                                                onKeyDown={(e) => {
                                                    if (e.key === "Enter" && e.currentTarget.value.trim()) {
                                                        notif.onAccept(e.currentTarget.value.trim());
                                                        e.currentTarget.value = "";
                                                        removeNotification(notif.id);
                                                    }
                                                }}
                                            />
                                            <button
                                                onClick={() => {
                                                    const input = document.getElementById(
                                                        `side-toast-response-${notif.id}`
                                                    ) as HTMLInputElement;
                                                    if (input?.value.trim()) {
                                                        notif.onAccept(input.value.trim());
                                                        input.value = "";
                                                        removeNotification(notif.id);
                                                    }
                                                }}
                                                className="px-3 py-1 bg-green-600 hover:bg-green-700 rounded text-sm flex items-center gap-1"
                                            >
                                                <CheckIcon size={14} />
                                            </button>
                                            <button
                                                onClick={() => {
                                                    notif.onReject();
                                                    removeNotification(notif.id);
                                                }}
                                                className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-sm flex items-center gap-1"
                                            >
                                                <Trash2Icon size={14} />
                                            </button>
                                        </div>
                                    </>
                                )}
                            </motion.div>
                        );
                    })}
                </AnimatePresence>
            </div>
        </div>
    );
}
