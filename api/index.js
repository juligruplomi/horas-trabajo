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

let usuarios = [
  { id: 1, email: 'admin@gruplomi.com', nombre: 'Admin', role: 'admin', password: bcrypt.hashSync('Admin2025!', 10) },
  { id: 2, email: 'supervisor@gruplomi.com', nombre: 'Supervisor', role: 'supervisor', password: bcrypt.hashSync('Sup2025!', 10) },
  { id: 3, email: 'juan@gruplomi.com', nombre: 'Juan Lopez', role: 'operario', password: bcrypt.hashSync('Juan2025!', 10) }
]

const roles = [
  { id: 1, nombre: 'admin', permisos: ['agregar_horas', 'editar_horas', 'eliminar_horas', 'supervisar_horas', 'editar_horas_otros', 'visualizar_horas_otros', 'editar_configuracion', 'gestionar_usuarios'] },
  { id: 2, nombre: 'supervisor', permisos: ['agregar_horas', 'editar_horas', 'eliminar_horas', 'supervisar_horas', 'editar_horas_otros', 'visualizar_horas_otros'] },
  { id: 3, nombre: 'operario', permisos: ['agregar_horas', 'editar_horas', 'eliminar_horas'] }
]

let configuracion = {
  empresa: {
    nombre: 'GrupLomi',
    logo: null,
    color_primario: '#0071e3',
    color_secundario: '#0066cc'
  },
  bienvenida: {
    titulo: 'GrupLomi Horas',
    subtitulo: 'Sistema de Control de Horas'
  },
  idioma: {
    idioma_principal: 'es',
    traducciones: {}
  },
  smtp: {
    host: '',
    puerto: 587,
    usuario: '',
    contraseña: ''
  }
}

let horas = [
  { id: 1, usuario_id: 3, fecha: '2025-11-10', tipo_trabajo: 'Averia', numero_aviso: 'AV-2025-0001', horas: 8, descripcion: 'Reparacion', estado: 'validado' },
  { id: 2, usuario_id: 3, fecha: '2025-11-09', tipo_trabajo: 'Obra', numero_aviso: 'OB-2025-0042', horas: 6, descripcion: 'Construccion', estado: 'pendiente' }
]

let avisos = [
  { id: 1, numero: 'AV-2025-0001', cliente: 'Cliente A', descripcion: 'Avería en línea 3', estado: 'en_curso', fecha_creacion: '2025-11-01', fecha: '2025-11-01', alertas_email: ['admin@gruplomi.com'] },
  { id: 2, numero: 'AV-2025-0002', cliente: 'Cliente B', descripcion: 'Fuga de agua', estado: 'en_curso', fecha_creacion: '2025-11-05', fecha: '2025-11-05', alertas_email: ['admin@gruplomi.com'] },
  { id: 3, numero: 'AV-2025-0003', cliente: 'Cliente A', descripcion: 'Motor averiado', estado: 'finalizado', fecha_creacion: '2025-10-20', fecha: '2025-10-20', alertas_email: [] }
]

let obras = [
  { id: 1, numero: 'OB-2025-0042', cliente: 'Cliente C', descripcion: 'Construcción nave 2', estado: 'en_curso', fecha_creacion: '2025-10-15', fecha: '2025-10-15', fecha_fin_estimada: '2025-12-15', alertas_email: ['admin@gruplomi.com'] },
  { id: 2, numero: 'OB-2025-0043', cliente: 'Cliente D', descripcion: 'Reforma local', estado: 'en_curso', fecha_creacion: '2025-11-01', fecha: '2025-11-01', fecha_fin_estimada: '2025-11-30', alertas_email: ['admin@gruplomi.com'] },
  { id: 3, numero: 'OB-2025-0041', cliente: 'Cliente B', descripcion: 'Cimentación', estado: 'finalizado', fecha_creacion: '2025-08-01', fecha: '2025-08-01', fecha_fin_estimada: '2025-10-01', alertas_email: [] }
]

let mantenimientos = [
  { id: 1, descripcion: 'Inspección compresor', tipo_alerta: 'mensual', proxima_alerta: '2025-12-10', cliente: 'Cliente A', estado: 'activo', fecha_creacion: '2025-11-01', primera_alerta: '2025-11-10', alertas_email: ['admin@gruplomi.com'] },
  { id: 2, descripcion: 'Cambio filtros', tipo_alerta: 'trimestral', proxima_alerta: '2025-12-31', cliente: 'Cliente C', estado: 'activo', fecha_creacion: '2025-09-15', primera_alerta: '2025-09-30', alertas_email: ['admin@gruplomi.com'] },
  { id: 3, descripcion: 'Revisión anual', tipo_alerta: 'anual', proxima_alerta: '2026-01-15', cliente: 'Cliente D', estado: 'activo', fecha_creacion: '2025-01-01', primera_alerta: '2025-01-15', alertas_email: ['admin@gruplomi.com'] }
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

const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'supervisor') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  next()
}

// ===== AUTH ENDPOINTS =====
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

// ===== HORAS ENDPOINTS =====
app.get('/horas', verifyToken, (req, res) => {
  let result = horas
  if (req.user.role === 'operario') {
    result = horas.filter(h => h.usuario_id === req.user.id)
  }
  res.json(result)
})

app.post('/horas', verifyToken, (req, res) => {
  const { fecha, tipo_trabajo, numero_aviso, horas: cant_horas, descripcion } = req.body
  if (!fecha || !tipo_trabajo || !numero_aviso || !cant_horas) {
    return res.status(400).json({ error: 'Missing required fields: fecha, tipo_trabajo, numero_aviso, horas' })
  }
  const newHora = {
    id: Math.max(...horas.map(h => h.id), 0) + 1,
    usuario_id: req.user.id,
    fecha,
    tipo_trabajo,
    numero_aviso,
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
  const { fecha, tipo_trabajo, numero_aviso, horas: cant_horas, descripcion, estado } = req.body
  horas[horaIdx] = {
    ...hora,
    fecha: fecha || hora.fecha,
    tipo_trabajo: tipo_trabajo || hora.tipo_trabajo,
    numero_aviso: numero_aviso || hora.numero_aviso,
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

// ===== AVISOS ENDPOINTS =====
app.get('/avisos', verifyToken, (req, res) => {
  res.json(avisos)
})

app.get('/avisos/activos', verifyToken, (req, res) => {
  res.json(avisos.filter(a => a.estado === 'en_curso'))
})

app.post('/avisos', verifyToken, verifyAdmin, (req, res) => {
  const { numero, cliente, descripcion, estado, fecha, alertas_email } = req.body
  if (!numero || !cliente || !descripcion || !fecha) {
    return res.status(400).json({ error: 'Missing required fields: numero, cliente, descripcion, fecha' })
  }
  const newAviso = {
    id: Math.max(...avisos.map(a => a.id), 0) + 1,
    numero,
    cliente,
    descripcion,
    estado: estado || 'en_curso',
    fecha_creacion: new Date().toISOString().split('T')[0],
    fecha: fecha,
    alertas_email: alertas_email || []
  }
  avisos.push(newAviso)
  res.status(201).json(newAviso)
})

app.put('/avisos/:id', verifyToken, verifyAdmin, (req, res) => {
  const avisoIdx = avisos.findIndex(a => a.id === parseInt(req.params.id))
  if (avisoIdx === -1) return res.status(404).json({ error: 'Aviso not found' })
  const { numero, cliente, descripcion, estado, fecha, alertas_email } = req.body
  avisos[avisoIdx] = {
    ...avisos[avisoIdx],
    numero: numero || avisos[avisoIdx].numero,
    cliente: cliente || avisos[avisoIdx].cliente,
    descripcion: descripcion || avisos[avisoIdx].descripcion,
    estado: estado || avisos[avisoIdx].estado,
    fecha: fecha || avisos[avisoIdx].fecha,
    alertas_email: alertas_email !== undefined ? alertas_email : avisos[avisoIdx].alertas_email
  }
  res.json(avisos[avisoIdx])
})

app.delete('/avisos/:id', verifyToken, verifyAdmin, (req, res) => {
  const avisoIdx = avisos.findIndex(a => a.id === parseInt(req.params.id))
  if (avisoIdx === -1) return res.status(404).json({ error: 'Aviso not found' })
  avisos.splice(avisoIdx, 1)
  res.json({ message: 'Deleted' })
})

// ===== OBRAS ENDPOINTS =====
app.get('/obras', verifyToken, (req, res) => {
  res.json(obras)
})

app.get('/obras/activas', verifyToken, (req, res) => {
  res.json(obras.filter(o => o.estado === 'en_curso'))
})

app.post('/obras', verifyToken, verifyAdmin, (req, res) => {
  const { numero, cliente, descripcion, estado, fecha, fecha_fin_estimada, alertas_email } = req.body
  if (!numero || !cliente || !descripcion || !fecha) {
    return res.status(400).json({ error: 'Missing required fields: numero, cliente, descripcion, fecha' })
  }
  const newObra = {
    id: Math.max(...obras.map(o => o.id), 0) + 1,
    numero,
    cliente,
    descripcion,
    estado: estado || 'en_curso',
    fecha_creacion: new Date().toISOString().split('T')[0],
    fecha: fecha,
    fecha_fin_estimada: fecha_fin_estimada || null,
    alertas_email: alertas_email || []
  }
  obras.push(newObra)
  res.status(201).json(newObra)
})

app.put('/obras/:id', verifyToken, verifyAdmin, (req, res) => {
  const obraIdx = obras.findIndex(o => o.id === parseInt(req.params.id))
  if (obraIdx === -1) return res.status(404).json({ error: 'Obra not found' })
  const { numero, cliente, descripcion, estado, fecha, fecha_fin_estimada, alertas_email } = req.body
  obras[obraIdx] = {
    ...obras[obraIdx],
    numero: numero || obras[obraIdx].numero,
    cliente: cliente || obras[obraIdx].cliente,
    descripcion: descripcion || obras[obraIdx].descripcion,
    estado: estado || obras[obraIdx].estado,
    fecha: fecha || obras[obraIdx].fecha,
    fecha_fin_estimada: fecha_fin_estimada || obras[obraIdx].fecha_fin_estimada,
    alertas_email: alertas_email !== undefined ? alertas_email : obras[obraIdx].alertas_email
  }
  res.json(obras[obraIdx])
})

app.delete('/obras/:id', verifyToken, verifyAdmin, (req, res) => {
  const obraIdx = obras.findIndex(o => o.id === parseInt(req.params.id))
  if (obraIdx === -1) return res.status(404).json({ error: 'Obra not found' })
  obras.splice(obraIdx, 1)
  res.json({ message: 'Deleted' })
})

// ===== MANTENIMIENTOS ENDPOINTS =====
app.get('/mantenimientos', verifyToken, (req, res) => {
  res.json(mantenimientos)
})

app.get('/mantenimientos/activos', verifyToken, (req, res) => {
  res.json(mantenimientos.filter(m => m.estado === 'activo'))
})

app.post('/mantenimientos', verifyToken, verifyAdmin, (req, res) => {
  const { descripcion, tipo_alerta, cliente, estado, fecha_creacion, primera_alerta, alertas_email } = req.body
  if (!descripcion || !tipo_alerta || !cliente || !primera_alerta) {
    return res.status(400).json({ error: 'Missing required fields: descripcion, tipo_alerta, cliente, primera_alerta' })
  }
  if (!['semanal', 'mensual', 'trimestral', 'anual'].includes(tipo_alerta)) {
    return res.status(400).json({ error: 'tipo_alerta must be: semanal, mensual, trimestral, anual' })
  }
  const newMant = {
    id: Math.max(...mantenimientos.map(m => m.id), 0) + 1,
    descripcion,
    tipo_alerta,
    cliente,
    estado: estado || 'activo',
    fecha_creacion: fecha_creacion || new Date().toISOString().split('T')[0],
    primera_alerta: primera_alerta,
    proxima_alerta: calcularProximaAlerta(tipo_alerta, primera_alerta),
    alertas_email: alertas_email || []
  }
  mantenimientos.push(newMant)
  res.status(201).json(newMant)
})

app.put('/mantenimientos/:id', verifyToken, verifyAdmin, (req, res) => {
  const mantIdx = mantenimientos.findIndex(m => m.id === parseInt(req.params.id))
  if (mantIdx === -1) return res.status(404).json({ error: 'Mantenimiento not found' })
  const { descripcion, tipo_alerta, cliente, estado, primera_alerta, alertas_email } = req.body
  mantenimientos[mantIdx] = {
    ...mantenimientos[mantIdx],
    descripcion: descripcion || mantenimientos[mantIdx].descripcion,
    tipo_alerta: tipo_alerta || mantenimientos[mantIdx].tipo_alerta,
    cliente: cliente || mantenimientos[mantIdx].cliente,
    estado: estado || mantenimientos[mantIdx].estado,
    primera_alerta: primera_alerta || mantenimientos[mantIdx].primera_alerta,
    proxima_alerta: tipo_alerta ? calcularProximaAlerta(tipo_alerta, primera_alerta || mantenimientos[mantIdx].primera_alerta) : mantenimientos[mantIdx].proxima_alerta,
    alertas_email: alertas_email !== undefined ? alertas_email : mantenimientos[mantIdx].alertas_email
  }
  res.json(mantenimientos[mantIdx])
})

app.delete('/mantenimientos/:id', verifyToken, verifyAdmin, (req, res) => {
  const mantIdx = mantenimientos.findIndex(m => m.id === parseInt(req.params.id))
  if (mantIdx === -1) return res.status(404).json({ error: 'Mantenimiento not found' })
  mantenimientos.splice(mantIdx, 1)
  res.json({ message: 'Deleted' })
})

// ===== USUARIOS ENDPOINTS =====
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

app.put('/usuarios/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  const usuarioIdx = usuarios.findIndex(u => u.id === parseInt(req.params.id))
  if (usuarioIdx === -1) return res.status(404).json({ error: 'Usuario not found' })
  
  const { email, nombre, role, password } = req.body
  if (email) usuarios[usuarioIdx].email = email
  if (nombre) usuarios[usuarioIdx].nombre = nombre
  if (role) usuarios[usuarioIdx].role = role
  if (password) usuarios[usuarioIdx].password = bcrypt.hashSync(password, 10)
  
  res.json({
    id: usuarios[usuarioIdx].id,
    email: usuarios[usuarioIdx].email,
    nombre: usuarios[usuarioIdx].nombre,
    role: usuarios[usuarioIdx].role
  })
})

app.delete('/usuarios/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  const usuarioIdx = usuarios.findIndex(u => u.id === parseInt(req.params.id))
  if (usuarioIdx === -1) return res.status(404).json({ error: 'Usuario not found' })
  usuarios.splice(usuarioIdx, 1)
  res.json({ message: 'Usuario deleted' })
})

// ===== ROLES ENDPOINTS =====
app.get('/roles', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  res.json(roles)
})

app.put('/roles/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  const rolIdx = roles.findIndex(r => r.id === parseInt(req.params.id))
  if (rolIdx === -1) return res.status(404).json({ error: 'Rol not found' })
  
  const { permisos } = req.body
  if (Array.isArray(permisos)) {
    roles[rolIdx].permisos = permisos
  }
  res.json(roles[rolIdx])
})

// ===== CONFIGURACION ENDPOINTS =====
app.get('/configuracion', verifyToken, verifyAdmin, (req, res) => {
  res.json(configuracion)
})

app.put('/configuracion/empresa', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  const { nombre, logo, color_primario, color_secundario } = req.body
  if (nombre) configuracion.empresa.nombre = nombre
  if (logo) configuracion.empresa.logo = logo
  if (color_primario) configuracion.empresa.color_primario = color_primario
  if (color_secundario) configuracion.empresa.color_secundario = color_secundario
  res.json(configuracion.empresa)
})

app.put('/configuracion/bienvenida', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  const { titulo, subtitulo } = req.body
  if (titulo) configuracion.bienvenida.titulo = titulo
  if (subtitulo) configuracion.bienvenida.subtitulo = subtitulo
  res.json(configuracion.bienvenida)
})

app.put('/configuracion/idioma', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  const { idioma_principal, traducciones } = req.body
  if (idioma_principal) configuracion.idioma.idioma_principal = idioma_principal
  if (traducciones) configuracion.idioma.traducciones = traducciones
  res.json(configuracion.idioma)
})

app.put('/configuracion/smtp', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' })
  }
  const { host, puerto, usuario, contraseña } = req.body
  if (host) configuracion.smtp.host = host
  if (puerto) configuracion.smtp.puerto = puerto
  if (usuario) configuracion.smtp.usuario = usuario
  if (contraseña) configuracion.smtp.contraseña = contraseña
  res.json(configuracion.smtp)
})

// ===== HEALTH ENDPOINT =====
app.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' })
})

// ===== FUNCIONES AUXILIARES =====
function calcularProximaAlerta(tipo_alerta, fecha_base) {
  const hoy = fecha_base ? new Date(fecha_base) : new Date()
  const proxima = new Date(hoy)
  
  switch(tipo_alerta) {
    case 'semanal':
      proxima.setDate(proxima.getDate() + 7)
      break
    case 'mensual':
      proxima.setMonth(proxima.getMonth() + 1)
      break
    case 'trimestral':
      proxima.setMonth(proxima.getMonth() + 3)
      break
    case 'anual':
      proxima.setFullYear(proxima.getFullYear() + 1)
      break
  }
  
  return proxima.toISOString().split('T')[0]
}

const PORT = process.env.PORT || 8000
app.listen(PORT, () => {
  console.log('🚀 Backend running on port ' + PORT)
})

module.exports = app
