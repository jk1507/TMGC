import { useState } from 'react'
import { motion } from 'framer-motion'
import Header from '../components/Header'
import RetroButton from '../components/RetroButton'
import InventoryCard from '../components/InventoryCard'
import RetroPanel from '../components/RetroPanel'

const QUICK_TEST_DOMAINS = [
  { domain: 'google.com', icon: '🔍', label: 'Search' },
  { domain: 'github.com', icon: '🐙', label: 'Code' },
  { domain: 'twitter.com', icon: '🐦', label: 'Social' },
  { domain: 'example.com', icon: '⚠️', label: 'Test' }
]

export default function Dashboard({ onStartScan }) {
  const [domainInput, setDomainInput] = useState('')
  const [selectedDomain, setSelectedDomain] = useState(null)

  const handleQuickTest = (domain) => {
    setSelectedDomain(domain)
    setDomainInput(domain)
  }

  const handleStartScan = () => {
    if (domainInput.trim()) {
      onStartScan(domainInput)
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
      <Header title="CYBER DETECTIVE" status="online" subtitle="THREAT INTELLIGENCE SCANNER" />

      <main className="max-w-6xl mx-auto px-4 py-8">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-8"
        >
          <motion.div variants={itemVariants} className="text-center py-4">
            <h2 className="text-2xl font-bold text-green-500 uppercase mb-2 tracking-widest text-glow-green">
              Domain Threat Analysis
            </h2>
            <p className="text-cyan-400 text-sm font-mono">
              Enter a domain to begin threat analysis
            </p>
          </motion.div>

          <motion.div variants={itemVariants}>
            <RetroPanel title="DOMAIN INPUT">
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-bold mb-1 text-gray-900">
                    TARGET DOMAIN:
                  </label>
                  <input
                    type="text"
                    placeholder="example.com"
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleStartScan()}
                    className="w-full px-3 py-2 bg-gray-100 border-2 border-gray-900 text-gray-900 font-mono text-sm focus:outline-none focus:bg-white focus:border-blue-600"
                  />
                </div>

                <div className="flex gap-2 justify-center">
                  <RetroButton
                    onClick={handleStartScan}
                    disabled={!domainInput.trim()}
                    size="lg"
                    className="flex-1"
                  >
                    Initiate Scan
                  </RetroButton>
                </div>
              </div>
            </RetroPanel>
          </motion.div>

          <motion.div variants={itemVariants}>
            <p className="text-xs font-bold text-green-500 mb-3 uppercase tracking-widest">
              ▶ Quick Test Domains:
            </p>
            <motion.div
              className="grid grid-cols-2 md:grid-cols-4 gap-4"
              variants={containerVariants}
              initial="hidden"
              animate="visible"
            >
              {QUICK_TEST_DOMAINS.map((item, idx) => (
                <motion.div key={idx} variants={itemVariants}>
                  <InventoryCard
                    title={item.label}
                    icon={item.icon}
                    onClick={() => handleQuickTest(item.domain)}
                    selected={selectedDomain === item.domain}
                  >
                    <span className="text-xs text-gray-700 font-mono">
                      {item.domain}
                    </span>
                  </InventoryCard>
                </motion.div>
              ))}
            </motion.div>
          </motion.div>

          <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <RetroPanel title="STATUS">
              <p className="text-xs font-bold text-gray-900">
                System: <span className="text-green-600">ONLINE</span>
              </p>
              <p className="text-xs text-gray-800 mt-1">
                Ready for threat analysis
              </p>
            </RetroPanel>

            <RetroPanel title="VERSION">
              <p className="text-xs font-bold text-gray-900">
                v2.0.0
              </p>
              <p className="text-xs text-gray-800 mt-1">
                Retro Cyber Detective
              </p>
            </RetroPanel>

            <RetroPanel title="FEATURES">
              <p className="text-xs font-bold text-gray-900">
                • Real-time Analysis
              </p>
              <p className="text-xs font-bold text-gray-900">
                • Threat Scoring
              </p>
              <p className="text-xs font-bold text-gray-900">
                • IP Mapping
              </p>
            </RetroPanel>
          </motion.div>

          <motion.div variants={itemVariants} className="text-center text-xs text-green-600 font-mono py-4">
            <p>{'>'} CYBER DETECTIVE READY</p>
            <p className="mt-1 text-green-500 animate-pulse">{'_'}</p>
          </motion.div>
        </motion.div>
      </main>
    </div>
  )
}