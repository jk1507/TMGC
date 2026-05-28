import { motion } from 'framer-motion'
import { useState, useEffect } from 'react'

export default function Header({ title = 'CYBER DETECTIVE', status = 'online', subtitle }) {
  const [time, setTime] = useState(new Date())

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(timer)
  }, [])

  const timeString = time.toLocaleTimeString()
  const dateString = time.toLocaleDateString()

  return (
    <motion.header
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      className="
        bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900
        border-b-4 border-green-500
        p-4 shadow-[0_0_20px_rgba(0,255,0,0.3)]
        font-mono
      "
    >
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-center mb-2">
          <motion.div
            initial={{ x: -20 }}
            animate={{ x: 0 }}
            transition={{ delay: 0.2 }}
            className="flex items-center gap-3"
          >
            <div className="w-4 h-4 rounded-full bg-green-500 shadow-[0_0_10px_rgba(0,255,0,0.8)] animate-pulse" />
            <h1 className="text-xl font-bold text-green-500 uppercase tracking-widest">
              {title}
            </h1>
          </motion.div>

          <motion.div
            initial={{ x: 20 }}
            animate={{ x: 0 }}
            transition={{ delay: 0.2 }}
            className="text-right"
          >
            <p className="text-xs text-green-400">
              {timeString}
            </p>
            <p className="text-xs text-green-400">
              {dateString}
            </p>
          </motion.div>
        </div>

        <div className="flex justify-between items-center">
          {subtitle && (
            <p className="text-xs text-cyan-400 font-bold uppercase">
              {subtitle}
            </p>
          )}
          
          <div className="ml-auto flex items-center gap-2">
            <span className={`
              text-xs font-bold uppercase
              ${status === 'online' ? 'text-green-500' : 'text-red-500'}
            `}>
              {status.toUpperCase()}
            </span>
            <motion.div
              animate={{ 
                boxShadow: [
                  `0 0 5px rgba(${status === 'online' ? '0,255,0' : '255,0,0'},0.5)`,
                  `0 0 15px rgba(${status === 'online' ? '0,255,0' : '255,0,0'},0.8)`,
                  `0 0 5px rgba(${status === 'online' ? '0,255,0' : '255,0,0'},0.5)`
                ]
              }}
              transition={{ duration: 2, repeat: Infinity }}
              className={`
                w-3 h-3 rounded-full
                ${status === 'online' ? 'bg-green-500' : 'bg-red-500'}
              `}
            />
          </div>
        </div>
      </div>
    </motion.header>
  )
}