import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  }
})

apiClient.interceptors.response.use(
  response => response,
  error => {
    console.error('API Error:', error)
    if (error.response?.status === 401) {
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export const api = {
  async healthCheck() {
    try {
      const response = await apiClient.get('/health')
      return response.data
    } catch (error) {
      console.error('Health check failed:', error)
      return null
    }
  },

  async analyzeDomain(domain) {
    try {
      const response = await apiClient.post('/api/analyze', {
        domain
      })
      return response.data
    } catch (error) {
      console.error('Domain analysis failed:', error)
      throw error
    }
  },

  async analyzeDomainStream(domain, onChunk) {
    try {
      const response = await fetch(`${API_BASE_URL}/api/analyze-stream`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain })
      })

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`)
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop()

        for (const line of lines) {
          if (line.trim()) {
            try {
              const data = JSON.parse(line)
              onChunk(data)
            } catch (e) {
              console.error('Failed to parse chunk:', line)
            }
          }
        }
      }

      if (buffer.trim()) {
        try {
          const data = JSON.parse(buffer)
          onChunk(data)
        } catch (e) {
          console.error('Failed to parse final chunk:', buffer)
        }
      }
    } catch (error) {
      console.error('Stream analysis failed:', error)
      throw error
    }
  },

  async batchAnalyze(domains) {
    try {
      const response = await apiClient.post('/api/batch-analyze', {
        domains
      })
      return response.data
    } catch (error) {
      console.error('Batch analysis failed:', error)
      throw error
    }
  },

  async getHistory(limit = 10, offset = 0) {
    try {
      const response = await apiClient.get('/api/history', {
        params: { limit, offset }
      })
      return response.data
    } catch (error) {
      console.error('Failed to fetch history:', error)
      throw error
    }
  }
}

export default api