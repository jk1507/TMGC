import { useState, useCallback } from 'react'
import api from '../utils/api'

export const useThreatAnalysis = () => {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [progress, setProgress] = useState(0)
  const [steps, setSteps] = useState([])
  const [results, setResults] = useState(null)

  const analyzeDomain = useCallback(async (domain) => {
    setLoading(true)
    setError(null)
    setProgress(0)
    setSteps([])
    setResults(null)

    try {
      const analysisSteps = []

      await api.analyzeDomainStream(domain, (chunk) => {
        if (chunk.type === 'step') {
          const stepProgress = Math.round((chunk.step / 8) * 100)
          setProgress(stepProgress)
          
          analysisSteps.push({
            step: chunk.step,
            title: chunk.title,
            status: chunk.status,
            message: chunk.message
          })
          
          setSteps([...analysisSteps])
        } else if (chunk.type === 'result') {
          setResults(chunk.data)
          setProgress(100)
        } else if (chunk.type === 'error') {
          throw new Error(chunk.message)
        }
      })
    } catch (err) {
      console.error('Analysis error:', err)
      setError(err.message || 'Analysis failed')
      setProgress(0)
    } finally {
      setLoading(false)
    }
  }, [])

  return {
    analyzeDomain,
    loading,
    error,
    progress,
    steps,
    results
  }
}

export default useThreatAnalysis