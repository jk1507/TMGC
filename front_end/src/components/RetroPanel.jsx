import { useState, useRef } from 'react'
import { motion } from 'framer-motion'

export default function RetroPanel({
  title,
  children,
  className = '',
  draggable = false,
  onClose
}) {
  const [position, setPosition] = useState({ x: 0, y: 0 })
  const [isDragging, setIsDragging] = useState(false)
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 })
  const panelRef = useRef(null)

  const handleMouseDown = (e) => {
    if (!draggable) return
    setIsDragging(true)
    setDragStart({
      x: e.clientX - position.x,
      y: e.clientY - position.y
    })
  }

  const handleMouseMove = (e) => {
    if (!isDragging) return
    setPosition({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    })
  }

  const handleMouseUp = () => {
    setIsDragging(false)
  }

  return (
    <motion.div
      ref={panelRef}
      drag={draggable}
      dragMomentum={false}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      className={`
        bg-gradient-to-b from-cyan-300 to-blue-400
        border-4 border-t-white border-l-white border-r-gray-600 border-b-gray-600
        shadow-[inset_1px_1px_0_rgba(255,255,255,0.8),inset_-1px_-1px_0_rgba(128,128,128,0.5),3px_3px_0_rgba(0,0,0,0.5)]
        ${draggable ? 'cursor-move' : ''}
        ${className}
      `}
      style={draggable ? { x: position.x, y: position.y } : {}}
    >
      <div
        onMouseDown={handleMouseDown}
        className="
          bg-gradient-to-r from-blue-600 to-cyan-500
          px-1 py-0 flex justify-between items-center
          border-b-2 border-gray-800 cursor-move
          select-none
        "
      >
        <p className="text-white text-xs font-bold font-mono tracking-wider">
          {title}
        </p>
        <div className="flex gap-1">
          <button className="w-5 h-5 bg-gradient-to-b from-gray-400 to-gray-600 border border-white text-gray-900 text-xs font-bold hover:bg-gray-300">
            _
          </button>
          <button className="w-5 h-5 bg-gradient-to-b from-gray-400 to-gray-600 border border-white text-gray-900 text-xs font-bold hover:bg-gray-300">
            □
          </button>
          {onClose && (
            <button 
              onClick={onClose}
              className="w-5 h-5 bg-gradient-to-b from-gray-400 to-gray-600 border border-white text-gray-900 text-xs font-bold hover:bg-red-400 hover:text-white"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      <div className="bg-gradient-to-b from-gray-400 to-gray-300 p-2">
        {children}
      </div>
    </motion.div>
  )
}