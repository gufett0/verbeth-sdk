import { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

export function CelebrationToast({ show, onClose }) {
  useEffect(() => {
    if (!show) return;
    const t = setTimeout(onClose, 3000);
    return () => clearTimeout(t);
  }, [show, onClose]);

  return (
    <AnimatePresence>
      {show && (
        <motion.div
          initial={{ opacity: 0, y: -30, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -20, scale: 0.98 }}
          transition={{ type: "spring", stiffness: 400, damping: 28 }}
          className="fixed top-8 left-1/2 z-[9999] -translate-x-1/2 bg-gray-900 border border-gray-700 rounded-2xl shadow-xl px-6 py-4 flex items-center gap-3 w-max"
          style={{ minWidth: 0 }}
        >
          <span className="inline-block">
            <svg width="32" height="32" fill="none" viewBox="0 0 24 24">
              <g>
                <path d="M7 21L3 17L13.5 6.5C13.7761 6.22386 14.2239 6.22386 14.5 6.5L17.5 9.5C17.7761 9.77614 17.7761 10.2239 17.5 10.5L7 21Z" fill="#3b82f6"/>
                <circle cx="19" cy="5" r="1.5" fill="#fbbf24"/>
                <circle cx="15" cy="3" r="1" fill="#34d399"/>
                <circle cx="21" cy="11" r="1" fill="#f472b6"/>
              </g>
            </svg>
          </span>
          <div>
            <div className="text-base font-semibold text-white">Identity Ready!</div>
            <div className="text-xs text-gray-300">Keys successfully derived 🎉</div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
