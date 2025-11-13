const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')

const app = express()

app.use(cors())
app.use(bodyParser.json())

const PROXY_URL = process.env.PROXY_URL || 'http://185.194.59.40:3001'
const PROXY_API_KEY = process.env.PROXY_API_KEY || 'GrupLomi2024ProxySecureKey_XyZ789'
const JWT_SECRET = process.env.JWT_SECRET_KEY || 'HorasTrabajo_JWT_Secret_2025'

const usuarios = [
  { id: 1, email: 'admin@gruplomi.com', nombre: 'Admin', role: 'admin', password: bcrypt.hashSync('Admin2025!', 10) },
  { id: 2, email: 'supervisor@gruplomi.com', nombre: 'Supervisor', role: 'supervisor', password: bcrypt.hashSync('Sup2025!', 10) },
  { id: 3, email: 'juan@gruplomi.com', nombre: 'Juan Lopez', role: 'operario', password: bcrypt.hashSync('Juan2025!', 10) }
]

const horas = [
  { id: 1, usuario_id: 3, fecha: '2025-11-10', tipo_trabajo: 'Averia', proyecto: 'Proyecto A', horas: 8, descripcion: 'Reparacion', estado: 'validado' },
  { id: 2, usuario_id: 3, fecha: '2025-11-09', tipo_trabajo: 'Obra', proyecto: 'Proyecto B', horas: 6, descripcion: 'Construccion', estado: 'pendiente' }
]

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'Token required' })
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    req.user = decoded
    next()
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' })
  }
}

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body
  const usuario = usuarios.find(u => u.email === email)
  if (!usuario || !bcrypt.compareSync(password, usuario.password)) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const token = jwt.sign({ id: usuario.id, email: usuario.email, role: usuario.role, nombre: usuario.nombre }, JWT_SECRET, { expiresIn: '24h' })
  res.json({ token, user: { id: usuario.id, email: usuario.email, nombre: usuario.nombre, role: usuario.role } })
})

app.get('/auth/me', verifyToken, (req, res) => {
  const usuario = usuarios.find(u => u.id === req.user.id)
  if (!usuario) return res.status(404).json({ error: 'User not found' })
  res.json({ id: usuario.id, email: usuario.email, nombre: usuario.nombre, role: usuario.role })
})

app.get('/horas', verifyToken, (req, res) => {
  let result = horas
  if (req.user.role === 'operario') {
    result = horas.filter(h => h.usuario_id === req.user.id)
  }
  res.json(result)
})

app.post('/horas', verifyToken, (req, res) => {
  const { fecha, tipo_trabajo, proyecto, horas: cant_horas, descripcion } = req.body
  if (!fecha || !tipo_trabajo || !proyecto || !cant_horas) {
    return res.status(400).json({ error: 'Missing required fields' })
  }
  const newHora = {
    id: Math.max(...horas.map(h => h.id), 0) + 1,
    usuario_id: req.user.id,
    fecha,
    tipo_trabajo,
    proyecto,
    horas: parseFloat(cant_horas),
    descripcion: descripcion || '',
    estado: 'pendiente'
  }
  horas.push(newHora)
  res.status(201).json(newHora)
})

app.put('/horas/:id', verifyToken, (req, res) => {
  const horaIdx = horas.findIndex(h => h.id === parseInt(req.params.id))
  if (horaIdx === -1) return res.status(404).json({ error: 'Hora not found' })
  const hora = horas[horaIdx]
  if (hora.usuario_id !== req.user.id && req.user.role === 'operario') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  const { fecha, tipo_trabajo, proyecto, horas: cant_horas, descripcion, estado } = req.body
  horas[horaIdx] = {
    ...hora,
    fecha: fecha || hora.fecha,
    tipo_trabajo: tipo_trabajo || hora.tipo_trabajo,
    proyecto: proyecto || hora.proyecto,
    horas: cant_horas ? parseFloat(cant_horas) : hora.horas,
    descripcion: descripcion || hora.descripcion,
    estado: estado || hora.estado
  }
  res.json(horas[horaIdx])
})

app.delete('/horas/:id', verifyToken, (req, res) => {
  const horaIdx = horas.findIndex(h => h.id === parseInt(req.params.id))
  if (horaIdx === -1) return res.status(404).json({ error: 'Hora not found' })
  const hora = horas[horaIdx]
  if (hora.usuario_id !== req.user.id && req.user.role === 'operario') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  horas.splice(horaIdx, 1)
  res.json({ message: 'Deleted' })
})

app.put('/horas/:id/validar', verifyToken, (req, res) => {
  if (req.user.role === 'operario') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  const horaIdx = horas.findIndex(h => h.id === parseInt(req.params.id))
  if (horaIdx === -1) return res.status(404).json({ error: 'Hora not found' })
  const { estado } = req.body
  horas[horaIdx].estado = estado === 'validado' ? 'validado' : 'rechazado'
  res.json(horas[horaIdx])
})

app.get('/usuarios', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  res.json(usuarios.map(u => ({
    id: u.id,
    email: u.email,
    nombre: u.nombre,
    role: u.role,
    activo: true
  })))
})

app.post('/usuarios', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  const { email, nombre, role, password } = req.body
  if (!email || !nombre || !role) {
    return res.status(400).json({ error: 'Missing required fields' })
  }
  const newUsuario = {
    id: Math.max(...usuarios.map(u => u.id), 0) + 1,
    email,
    nombre,
    role,
    password: bcrypt.hashSync(password || 'TempPassword2025!', 10)
  }
  usuarios.push(newUsuario)
  res.status(201).json({
    id: newUsuario.id,
    email: newUsuario.email,
    nombre: newUsuario.nombre,
    role: newUsuario.role
  })
})

app.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' })
})

const PORT = process.env.PORT || 8000
app.listen(PORT, () => {
  console.log('Backend running on port ' + PORT)
})

module.exports = app
