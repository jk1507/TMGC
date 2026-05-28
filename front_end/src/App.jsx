import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import Dashboard from './pages/Dashboard'
import ResultsPage from './pages/ResultsPage'
import CRTEffect from './components/CRTEffect'

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard')
  const [analysisData, setAnalysisData] = useState(null)
  const [domain, setDomain] = useState('')

  const handleStartScan = (domainInput) => {
    setDomain(domainInput)
    setCurrentPage('results')
  }

  const handleScanAgain = () => {
    setCurrentPage('dashboard')
    setAnalysisData(null)
    setDomain('')
  }

  const pageVariants = {
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: -20 }
  }

  const pageTransition = {
    duration: 0.5,
    ease: 'easeInOut'
  }

  return (
    <CRTEffect>
      <div className="min-h-screen grid-bg">
        <AnimatePresence mode="wait">
          {currentPage === 'dashboard' ? (
            <motion.div
              key="dashboard"
              variants={pageVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              transition={pageTransition}
            >
              <Dashboard onStartScan={handleStartScan} />
            </motion.div>
          ) : (
            <motion.div
              key="results"
              variants={pageVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              transition={pageTransition}
            >
              <ResultsPage 
                domain={domain} 
                onScanAgain={handleScanAgain}
                analysisData={analysisData}
                setAnalysisData={setAnalysisData}
              />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </CRTEffect>
  )
}

export default App