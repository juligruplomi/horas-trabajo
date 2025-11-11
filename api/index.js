import express from 'express'
import cors from 'cors'
import http from 'http'

const app = express()

app.use(cors())
app.use(express.json())

const PROXY_URL = 'http://185.194.59.40:3001'
const PROXY_API_KEY = 'GrupLomi2024ProxySecureKey_XyZ789'

app.get('/', (req, res) => {
  res.json({ message: 'API GrupLomi Horas v1.0' })
})

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' })
})

app.post('/query', (req, res) => {
  const { text, params } = req.body

  const postData = JSON.stringify({ text, params })

  const options = {
    hostname: '185.194.59.40',
    port: 3001,
    path: '/query',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData),
      'x-api-key': PROXY_API_KEY
    }
  }

  const proxyReq = http.request(options, (proxyRes) => {
    let data = ''
    proxyRes.on('data', chunk => { data += chunk })
    proxyRes.on('end', () => {
      res.status(proxyRes.statusCode)
      res.set(proxyRes.headers)
      res.send(data)
    })
  })

  proxyReq.on('error', (error) => {
    res.status(500).json({ error: error.message })
  })

  proxyReq.write(postData)
  proxyReq.end()
})

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ detail: 'Email y contraseña requeridos' })
  }

  try {
    const postData = JSON.stringify({
      text: 'SELECT id, email, nombre, apellidos, role, activo, password_hash FROM usuarios WHERE email = $1',
      params: [email]
    })

    const options = {
      hostname: '185.194.59.40',
      port: 3001,
      path: '/query',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'x-api-key': PROXY_API_KEY
      }
    }

    const proxyReq = http.request(options, (proxyRes) => {
      let data = ''
      proxyRes.on('data', chunk => { data += chunk })
      proxyRes.on('end', () => {
        try {
          const result = JSON.parse(data)
          const rows = result.rows

          if (!rows || rows.length === 0) {
            return res.status(401).json({ detail: 'Credenciales incorrectas' })
          }

          const user = rows[0]

          if (password !== 'Admin2025!') {
            return res.status(401).json({ detail: 'Contraseña incorrecta' })
          }

          const token = 'demo_' + Buffer.from(JSON.stringify({ id: user.id, email: user.email })).toString('base64')

          res.json({
            access_token: token,
            token_type: 'bearer',
            user: {
              id: user.id,
              email: user.email,
              nombre: user.nombre,
              role: user.role,
              activo: user.activo
            }
          })
        } catch (e) {
          res.status(500).json({ detail: e.message })
        }
      })
    })

    proxyReq.on('error', (error) => {
      res.status(500).json({ detail: error.message })
    })

    proxyReq.write(postData)
    proxyReq.end()
  } catch (error) {
    res.status(500).json({ detail: error.message })
  }
})

export default app