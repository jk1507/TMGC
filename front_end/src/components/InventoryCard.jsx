import { motion } from 'framer-motion'

export default function InventoryCard({
  title,
  icon,
  onClick,
  selected = false,
  children,
  className = ''
}) {
  return (
    <motion.div
      whileHover={{ y: -2 }}
      whileTap={{ y: 2 }}
      onClick={onClick}
      className={`
        bg-gradient-to-b from-gray-400 to-gray-600
        border-4 cursor-pointer
        shadow-[3px_3px_0px_rgba(0,0,0,0.8),inset_1px_1px_0px_rgba(255,255,255,0.8)]
        transition-all duration-100
        p-4 min-h-24 flex flex-col items-center justify-center
        relative
        ${selected ? 'border-cyan-400 shadow-[0_0_10px_rgba(0,255,255,0.5)]' : 'border-green-500'}
        ${className}
      `}
    >
      <div className="absolute inset-0 bg-gradient-to-b from-white/20 to-transparent pointer-events-none" />
      
      <div className="relative z-10 text-center">
        {icon && (
          <div className="text-4xl mb-2 font-bold text-gray-900">
            {icon}
          </div>
        )}
        {title && (
          <p className="font-bold text-gray-900 text-sm uppercase tracking-wider">
            {title}
          </p>
        )}
        {children && (
          <div className="mt-2 text-xs text-gray-800">
            {children}
          </div>
        )}
      </div>
    </motion.div>
  )
}