import { useEffect } from 'react'
import gsap from 'gsap'

export default function CRTEffect({ children }) {
  useEffect(() => {
    const flicker = () => {
      const overlay = document.querySelector('.crt-overlay')
      if (!overlay) return

      gsap.to(overlay, {
        opacity: gsap.utils.random(0.97, 0.99),
        duration: gsap.utils.random(0.02, 0.05),
        ease: 'none',
        onComplete: flicker
      })
    }

    flicker()

    return () => {
      gsap.killTweensOf('.crt-overlay')
    }
  }, [])

  return (
    <div className="relative w-full h-full overflow-hidden">
      {children}
      
      <div className="crt-scanlines fixed top-0 left-0 w-full h-full pointer-events-none z-50" />
      
      <div 
        className="crt-overlay fixed top-0 left-0 w-full h-full pointer-events-none z-50"
        style={{
          background: 'repeating-linear-gradient(0deg, rgba(0,0,0,0.03), rgba(0,0,0,0.03) 1px, transparent 1px, transparent 2px)',
          opacity: 0.97
        }}
      />

      <div className="fixed top-0 left-0 w-full h-full pointer-events-none z-50 bg-radial-gradient shadow-[inset_0_0_80px_rgba(0,0,0,0.3)]" />
    </div>
  )
}