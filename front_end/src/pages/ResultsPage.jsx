import { useEffect } from 'react'
import { motion } from 'framer-motion'
import Header from '../components/Header'
import RetroButton from '../components/RetroButton'
import TerminalLog from '../components/TerminalLog'
import ProgressBar from '../components/ProgressBar'
import InventoryCard from '../components/InventoryCard'
import RetroPanel from '../components/RetroPanel'
import useThreatAnalysis from '../hooks/useThreatAnalysis'

export default function ResultsPage({ domain, onScanAgain, analysisData, setAnalysisData }) {
  const { analyzeDomain, loading, error, progress, steps, results } = useThreatAnalysis()

  useEffect(() => {
    if (domain && !analysisData) {
      analyzeDomain(domain)
    }
  }, [domain, analysisData, analyzeDomain])

  const terminalLogs = steps.map(step => ({
    type: step.status === 'complete' ? 'success' : step.status === 'error' ? 'error' : 'info',
    message: `[${step.step}/8] ${step.title}: ${step.message}`
  }))

  const getThreatLevel = () => {
    if (!results?.threat_score) return 'UNKNOWN'
    const score = results.threat_score
    if (score >= 80) return 'CRITICAL'
    if (score >= 60) return 'HIGH'
    if (score >= 40) return 'MEDIUM'
    if (score >= 20) return 'LOW'
    return 'SAFE'
  }

  const getThreatColor = () => {
    const level = getThreatLevel()
    switch (level) {
      case 'CRITICAL': return 'text-red-500'
      case 'HIGH': return 'text-red-400'
      case 'MEDIUM': return 'text-yellow-500'
      case 'LOW': return 'text-green-400'
      case 'SAFE': return 'text-green-500'
      default: return 'text-cyan-400'
    }
  }

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.2
      }
    }
  }

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.5 }
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-950 to-black">
      <Header
        title="THREAT ANALYSIS"
        status={loading ? 'scanning' : 'complete'}
        subtitle={`DOMAIN: ${domain.toUpperCase()}`}
      />

      <main className="max-w-6xl mx-auto px-4 py-8">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-6"
        >
          {loading && (
            <motion.div variants={itemVariants}>
              <RetroPanel title="SCAN PROGRESS">
                <div className="space-y-3">
                  <ProgressBar
                    progress={progress}
                    max={100}
                    color="green"
                    showLabel={true}
                  />
                  <p className="text-xs font-mono text-gray-900 text-center">
                    {progress}% COMPLETE
                  </p>
                </div>
              </RetroPanel>
            </motion.div>
          )}

          <motion.div variants={itemVariants}>
            <RetroPanel title="ANALYSIS LOG">
              <TerminalLog logs={terminalLogs} height="400px" />
            </RetroPanel>
          </motion.div>

          {results && !loading && (
            <>
              <motion.div variants={itemVariants}>
                <InventoryCard
                  title="THREAT SCORE"
                  icon={results.threat_score >= 60 ? '⚠️' : '✓'}
                >
                  <div className={`text-3xl font-bold ${getThreatColor()}`}>
                    {results.threat_score}
                  </div>
                  <div className={`text-sm font-bold uppercase mt-2 ${getThreatColor()}`}>
                    {getThreatLevel()}
                  </div>
                </InventoryCard>
              </motion.div>

              <motion.div variants={itemVariants}>
                <RetroPanel title="THREAT BREAKDOWN">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {results.threats && results.threats.map((threat, idx) => (
                      <motion.div
                        key={idx}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: idx * 0.1 }}
                        className="bg-gray-200 p-3 border-2 border-gray-900"
                      >
                        <p className="text-xs font-bold text-gray-900 uppercase">
                          {threat.type}
                        </p>
                        <p className="text-xs text-gray-800 mt-1">
                          {threat.description}
                        </p>
                        <div className="text-right mt-2">
                          <span className={`text-xs font-bold ${threat.severity === 'high' ? 'text-red-600' : 'text-green-600'}`}>
                            {threat.severity.toUpperCase()}
                          </span>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </RetroPanel>
              </motion.div>

              {results.additional_info && (
                <motion.div variants={itemVariants}>
                  <RetroPanel title="ADDITIONAL INFO">
                    <div className="text-xs text-gray-900 font-mono space-y-2">
                      {Object.entries(results.additional_info).map(([key, value]) => (
                        <div key={key} className="flex justify-between">
                          <span className="font-bold">{key}:</span>
                          <span>{String(value)}</span>
                        </div>
                      ))}
                    </div>
                  </RetroPanel>
                </motion.div>
              )}
            </>
          )}

          {error && !loading && (
            <motion.div
              variants={itemVariants}
              className="bg-red-900 border-2 border-red-500 p-4 text-red-100 font-mono text-sm"
            >
              <p className="font-bold">ERROR: {error}</p>
            </motion.div>
          )}

          <motion.div variants={itemVariants} className="flex gap-4 justify-center pt-4">
            <RetroButton
              onClick={onScanAgain}
              size="lg"
              variant="primary"
            >
              Scan Again
            </RetroButton>

            <RetroButton
              size="lg"
              variant="success"
              onClick={() => {
                if (results) {
                  const csv = generateCSVReport(domain, results)
                  downloadReport(csv, domain)
                }
              }}
              disabled={!results}
            >
              Export Report
            </RetroButton>
          </motion.div>

          {loading && (
            <motion.div
              variants={itemVariants}
              className="text-center text-green-500 font-mono text-sm"
            >
              <motion.p
                animate={{ opacity: [0.5, 1] }}
                transition={{ duration: 1, repeat: Infinity }}
              >
                {'> SCANNING IN PROGRESS...'}
              </motion.p>
            </motion.div>
          )}
        </motion.div>
      </main>
    </div>
  )
}

function generateCSVReport(domain, results) {
  let csv = `Domain Threat Analysis Report\n`
  csv += `Domain,${domain}\n`
  csv += `Threat Score,${results.threat_score}\n`
  csv += `Analysis Date,${new Date().toISOString()}\n\n`
  csv += `Threats Found\n`
  csv += `Type,Description,Severity\n`

  if (results.threats) {
    results.threats.forEach(threat => {
      csv += `"${threat.type}","${threat.description}","${threat.severity}"\n`
    })
  }

  return csv
}

function downloadReport(csv, domain) {
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `threat-analysis-${domain}-${Date.now()}.csv`
  a.click()
  window.URL.revokeObjectURL(url)
}