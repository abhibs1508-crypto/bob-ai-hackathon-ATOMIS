import { motion } from 'framer-motion';

const priorityMap = {
  critical: { label: 'Critical', cls: 'badge-critical', dot: 'dot-critical' },
  high:     { label: 'High',     cls: 'badge-high',     dot: 'dot-high'     },
  medium:   { label: 'Medium',   cls: 'badge-medium',   dot: 'dot-medium'   },
  low:      { label: 'Low',      cls: 'badge-low',      dot: 'dot-low'      },
};

export default function PriorityBadge({ priority, pulse = false }) {
  const p = priorityMap[priority?.toLowerCase()] || priorityMap.low;
  return (
    <motion.span
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className={`badge ${p.cls}`}
    >
      <span className={`dot ${p.dot} ${pulse && priority === 'critical' ? 'animate-pulse-critical' : ''}`} />
      {p.label}
    </motion.span>
  );
}
