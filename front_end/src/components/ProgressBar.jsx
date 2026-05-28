import { motion } from 'framer-motion'

export default function ProgressBar({
  progress = 0,
  max = 100,
  height = 'h-8',
  color = 'green',
  showLabel = true,
  animated = true,
  className = ''
}) {
  const percentage = Math.min((progress / max) * 100, 100)

  const colorClasses = {
    green: 'from-green-500 to-green-400 border-green-500',
    cyan: 'from-cyan-500 to-cyan-400 border-cyan-500',
    magenta: 'from-magenta-500 to-magenta-400 border-magenta-500',
    yellow: 'from-yellow-500 to-yellow-400 border-yellow-500',
    red: 'from-red-500 to-red-400 border-red-500'
  }

  return (
    <div className={`w-full ${className}`}>
      <div className={`
        bg-gray-900 border-2 ${colorClasses[color]}
        shadow-[inset_0_0_5px_rgba(0,0,0,0.5),0_0_10px_rgba(0,255,0,0.2)]
        relative overflow-hidden ${height}
      `}>
        <motion.div
          className={`
            h-full bg-gradient-to-r ${colorClasses[color]}
            shadow-[0_0_10px_currentColor]
            relative
          `}
          initial={{ width: 0 }}
          animate={{ width: `${percentage}%` }}
          transition={animated ? { duration: 0.5, ease: 'easeOut' } : { duration: 0 }}
        >
          <div className="
            absolute inset-0
            bg-repeat-x opacity-30
            animate-pulse
          " />
        </motion.div>

        <div className="absolute inset-0 opacity-10 bg-[linear-gradient(45deg,transparent_25%,rgba(68,68,68,.2)_25%,rgba(68,68,68,.2)_50%,transparent_50%,transparent_75%,rgba(68,68,68,.2)_75%,rgba(68,68,68,.2))] bg-[length:20px_20px]" />
      </div>

      {showLabel && (
        <div className="text-xs font-mono text-center mt-1">
          <span className="text-green-500">{`[`}</span>
          <span className={`text-${color}-400`}>
            {Math.round(percentage)}%
          </span>
          <span className="text-green-500">{`]`}</span>
        </div>
      )}
    </div>
  )
}