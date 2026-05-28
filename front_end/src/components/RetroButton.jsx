import { motion } from 'framer-motion'

export default function RetroButton({
  children,
  onClick,
  disabled = false,
  className = '',
  variant = 'primary',
  size = 'md',
  ...props
}) {
  const sizeClasses = {
    sm: 'px-3 py-1 text-xs',
    md: 'px-4 py-2 text-sm',
    lg: 'px-6 py-3 text-base',
    xl: 'px-8 py-4 text-lg'
  }

  const variantClasses = {
    primary: 'border-green-500 text-green-500 bg-gray-900 hover:border-cyan-400 hover:text-cyan-400',
    danger: 'border-red-500 text-red-500 bg-gray-900 hover:border-yellow-400 hover:text-yellow-400',
    success: 'border-green-400 text-green-400 bg-gray-900 hover:text-green-300',
    warning: 'border-yellow-500 text-yellow-500 bg-gray-900 hover:border-red-500 hover:text-red-500'
  }

  const handleClick = () => {
    if (!disabled && onClick) {
      onClick()
    }
  }

  return (
    <motion.button
      whileHover={{ y: -2 }}
      whileTap={{ y: 1 }}
      onClick={handleClick}
      disabled={disabled}
      className={`
        font-mono font-bold uppercase tracking-wider
        border-4 transition-all duration-100
        shadow-[3px_3px_0px_rgba(0,255,0,0.5),6px_6px_0px_rgba(0,0,0,0.5)]
        hover:shadow-[2px_2px_0px_rgba(0,255,255,0.7),4px_4px_0px_rgba(0,0,0,0.3)]
        disabled:opacity-50 disabled:cursor-not-allowed
        ${sizeClasses[size]}
        ${variantClasses[variant]}
        ${disabled ? 'opacity-50' : ''}
        ${className}
      `}
      {...props}
    >
      {children}
    </motion.button>
  )
}