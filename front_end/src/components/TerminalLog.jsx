import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'

export default function TerminalLog({ logs = [], autoScroll = true, height = '300px' }) {
  const scrollRef = useRef(null)
  const [displayedLogs, setDisplayedLogs] = useState([])

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [logs, autoScroll])

  useEffect(() => {
    setDisplayedLogs(logs)
  }, [logs])

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="
        bg-gray-900 border-2 border-green-500
        font-mono text-xs text-green-400
        overflow-hidden flex flex-col
        shadow-[0_0_10px_rgba(0,255,0,0.3),inset_0_0_5px_rgba(0,255,0,0.1)]
      "
      style={{ height }}
    >
      <div
        ref={scrollRef}
        className="
          flex-1 overflow-y-auto p-3
          space-y-1
        "
      >
        {displayedLogs.length === 0 ? (
          <p className="text-green-500 animate-pulse">
            {'> TERMINAL READY..'}
          </p>
        ) : (
          displayedLogs.map((log, idx) => (
            <motion.div
              key={idx}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: idx * 0.05 }}
              className={`
                font-mono text-xs
                ${log.type === 'error' ? 'text-red-500' : ''}
                ${log.type === 'success' ? 'text-green-300' : ''}
                ${log.type === 'warning' ? 'text-yellow-500' : ''}
                ${log.type === 'info' ? 'text-cyan-400' : 'text-green-400'}
              `}
            >
              <span className="text-green-600">{`>`}</span> {log.message}
            </motion.div>
          ))
        )}
      </div>

      <div className="px-3 py-1 bg-gray-800 border-t border-green-500 flex items-center gap-1">
        <span className="text-green-500">{`>`}</span>
        <span className="w-2 h-4 bg-green-500 animate-pulse" />
      </div>
    </motion.div>
  )
}