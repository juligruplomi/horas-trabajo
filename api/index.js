const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const fetch = require('node-fetch')
const AbortController = require('abort-controller')

const app = express()

app.use(cors())
app.use(bodyParser.json({ limit: '10mb' }))

const PROXY_URL = process.env.PROXY_URL || 'http://185.194.59.40:3001'
const PROXY_API_KEY = process.env.PROXY_API_KEY || 'GrupLomi2024ProxySecureKey_XyZ789'
const JWT_SECRET = process.env.JWT_SECRET_KEY || 'HorasTrabajo_JWT_Secret_2025'

// ===== SISTEMA DE CACHÉ ULTRA-RÁPIDO =====
const CACHE = {
  usuarios: [],
  roles: [],
  configuracion: null,
  horas: [],
  avisos: [],
  obras: [],
  mantenimientos: [],
  lastSync: {},
  initialized: false
}

// Tiempo máximo de caché antes de refrescar (5 minutos)
const CACHE_TTL = 5 * 60 * 1000

// ===== LOGS EN MEMORIA =====
const logsEnMemoria = []
const MAX_LOGS = 200

function registrarLog(tipo, accion, detalles = {}, usuario = null) {
  const log = {
    id: Date.now(),
    tipo,
    accion,
    detalles: typeof detalles === 'string' ? detalles : JSON.stringify(detalles),
    usuario: usuario || 'sistema',
    fecha: new Date().toISOString()
  }
  logsEnMemoria.unshift(log)
  if (logsEnMemoria.length > MAX_LOGS) logsEnMemoria.pop()
  console.log(`${tipo === 'error' ? '❌' : tipo === 'success' ? '✅' : 'ℹ️'} ${accion}`)
  return log
}

// ===== QUERY CON TIMEOUT CORTO Y FALLBACK =====
async function dbQuery(text, params = [], timeout = 8000) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeout)
  
  try {
    const response = await fetch(`${PROXY_URL}/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': PROXY_API_KEY },
      body: JSON.stringify({ text, params }),
      signal: controller.signal
    })
    
    clearTimeout(timeoutId)
    
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    
    const data = await response.json()
    if (data.error) throw new Error(data.error)
    
    return { rows: data.rows || [], success: true }
  } catch (error) {
    clearTimeout(timeoutId)
    console.error(`DB Error (${timeout}ms): ${error.message}`)
    return { rows: [], success: false, error: error.message }
  }
}

// ===== ESCRITURA EN SEGUNDO PLANO (NO BLOQUEA) =====
function dbWriteAsync(text, params = []) {
  // Fire and forget - no esperamos respuesta
  dbQuery(text, params, 15000).catch(err => {
    console.error('Async write failed:', err.message)
  })
}

// ===== DATOS POR DEFECTO =====
const DEFAULT_USUARIOS = [
  { id: 1, email: 'admin@gruplomi.com', nombre: 'Admin', role: 'admin', password: bcrypt.hashSync('Admin2025!', 10) },
  { id: 2, email: 'supervisor@gruplomi.com', nombre: 'Supervisor', role: 'supervisor', password: bcrypt.hashSync('Sup2025!', 10) },
  { id: 3, email: 'juan@gruplomi.com', nombre: 'Juan Lopez', role: 'operario', password: bcrypt.hashSync('Juan2025!', 10) }
]

const DEFAULT_ROLES = [
  { id: 1, nombre: 'admin', permisos: ['agregar_horas', 'editar_horas', 'eliminar_horas', 'supervisar_horas', 'editar_horas_otros', 'visualizar_horas_otros', 'editar_configuracion', 'gestionar_usuarios'] },
  { id: 2, nombre: 'supervisor', permisos: ['agregar_horas', 'editar_horas', 'eliminar_horas', 'supervisar_horas', 'editar_horas_otros', 'visualizar_horas_otros'] },
  { id: 3, nombre: 'operario', permisos: ['agregar_horas', 'editar_horas', 'eliminar_horas'] }
]

const DEFAULT_CONFIG = {
  empresa: { nombre: 'GrupLomi', logo: null, color_primario: '#0071e3', color_secundario: '#0066cc' },
  bienvenida: { titulo: 'GrupLomi Horas', subtitulo: 'Sistema de Control de Horas' },
  idioma: { idioma_principal: 'es', traducciones: {} },
  smtp: { host: '', puerto: 587, usuario: '', contraseña: '' }
}

// Inicializar caché con valores por defecto
CACHE.usuarios = [...DEFAULT_USUARIOS]
CACHE.roles = [...DEFAULT_ROLES]
CACHE.configuracion = JSON.parse(JSON.stringify(DEFAULT_CONFIG))

// ===== INICIALIZACIÓN CON REINTENTOS =====
async function initializeCache() {
  console.log('🚀 Iniciando carga de caché...')
  
  // Crear tablas (no bloqueante)
  const createTables = async () => {
    await dbQuery(`CREATE TABLE IF NOT EXISTS configuracion_horas (clave VARCHAR(100) PRIMARY KEY, valor JSONB NOT NULL)`)
    await dbQuery(`CREATE TABLE IF NOT EXISTS usuarios_horas (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL, nombre VARCHAR(255) NOT NULL, role VARCHAR(50) NOT NULL, password VARCHAR(255) NOT NULL, activo BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`)
    await dbQuery(`CREATE TABLE IF NOT EXISTS horas_trabajo (id SERIAL PRIMARY KEY, usuario_id INTEGER, fecha DATE NOT NULL, tipo_trabajo VARCHAR(50) NOT NULL, numero_aviso VARCHAR(100), horas DECIMAL(4,2) NOT NULL, descripcion TEXT, estado VARCHAR(20) DEFAULT 'pendiente', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`)
    await dbQuery(`CREATE TABLE IF NOT EXISTS avisos_trabajo (id SERIAL PRIMARY KEY, numero VARCHAR(50) UNIQUE NOT NULL, cliente VARCHAR(255) NOT NULL, descripcion TEXT, estado VARCHAR(20) DEFAULT 'en_curso', fecha DATE, alertas_email TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`)
    await dbQuery(`CREATE TABLE IF NOT EXISTS obras_trabajo (id SERIAL PRIMARY KEY, numero VARCHAR(50) UNIQUE NOT NULL, cliente VARCHAR(255) NOT NULL, descripcion TEXT, estado VARCHAR(20) DEFAULT 'en_curso', fecha DATE, fecha_fin_estimada DATE, alertas_email TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`)
    await dbQuery(`CREATE TABLE IF NOT EXISTS mantenimientos_trabajo (id SERIAL PRIMARY KEY, descripcion TEXT NOT NULL, cliente VARCHAR(255) NOT NULL, tipo_alerta VARCHAR(20), primera_alerta DATE, proxima_alerta DATE, estado VARCHAR(20) DEFAULT 'activo', alertas_email TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`)
    await dbQuery(`CREATE TABLE IF NOT EXISTS roles_horas (id SERIAL PRIMARY KEY, nombre VARCHAR(50) UNIQUE NOT NULL, permisos JSONB DEFAULT '[]')`)
  }
  
  // Cargar datos con reintento
  const loadDataWithRetry = async (maxRetries = 3) => {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      console.log(`📡 Intento ${attempt}/${maxRetries} de carga desde BD...`)
      
      const [configRes, usersRes, rolesRes, horasRes, avisosRes, obrasRes, mantRes] = await Promise.all([
        dbQuery("SELECT valor FROM configuracion_horas WHERE clave = 'general'", [], 20000),
        dbQuery('SELECT * FROM usuarios_horas WHERE activo = true ORDER BY id', [], 20000),
        dbQuery('SELECT * FROM roles_horas ORDER BY id', [], 20000),
        dbQuery('SELECT * FROM horas_trabajo ORDER BY fecha DESC, id DESC LIMIT 1000', [], 20000),
        dbQuery('SELECT * FROM avisos_trabajo ORDER BY id DESC', [], 20000),
        dbQuery('SELECT * FROM obras_trabajo ORDER BY id DESC', [], 20000),
        dbQuery('SELECT * FROM mantenimientos_trabajo ORDER BY id DESC', [], 20000)
      ])
      
      // Contar éxitos
      const successes = [configRes, usersRes, rolesRes, horasRes, avisosRes, obrasRes, mantRes].filter(r => r.success).length
      
      if (successes >= 4) { // Al menos 4 de 7 consultas exitosas
        // Actualizar caché con datos válidos
        if (configRes.success && configRes.rows.length > 0) {
          CACHE.configuracion = { ...DEFAULT_CONFIG, ...configRes.rows[0].valor }
        }
        
        if (usersRes.success && usersRes.rows.length > 0) {
          CACHE.usuarios = usersRes.rows.map(u => ({
            id: u.id, email: u.email, nombre: u.nombre, role: u.role, password: u.password, activo: u.activo
          }))
        }
        
        if (rolesRes.success && rolesRes.rows.length > 0) {
          CACHE.roles = rolesRes.rows.map(r => ({
            id: r.id, nombre: r.nombre, permisos: Array.isArray(r.permisos) ? r.permisos : []
          }))
        } else {
          // Insertar roles por defecto
          for (const role of DEFAULT_ROLES) {
            await dbQuery('INSERT INTO roles_horas (nombre, permisos) VALUES ($1, $2) ON CONFLICT (nombre) DO NOTHING', [role.nombre, JSON.stringify(role.permisos)])
          }
        }
        
        if (horasRes.success) CACHE.horas = horasRes.rows
        if (avisosRes.success) CACHE.avisos = avisosRes.rows
        if (obrasRes.success) CACHE.obras = obrasRes.rows
        if (mantRes.success) CACHE.mantenimientos = mantRes.rows
        
        CACHE.lastSync.all = Date.now()
        CACHE.initialized = true
        
        console.log(`✅ Caché cargado: ${CACHE.usuarios.length} usuarios, ${CACHE.horas.length} horas, SMTP: ${CACHE.configuracion?.smtp?.host || 'no config'}`)
        return true
      }
      
      console.log(`⚠️ Intento ${attempt} parcial (${successes}/7 exitosas), reintentando...`)
      await new Promise(r => setTimeout(r, 2000)) // Esperar 2s antes de reintentar
    }
    
    console.log('❌ No se pudo cargar caché completo, usando valores por defecto')
    CACHE.initialized = true
    return false
  }
  
  try {
    await createTables()
    await loadDataWithRetry()
    registrarLog('success', 'Sistema iniciado', { version: '4.4' })
  } catch (error) {
    console.error('Error inicializando:', error.message)
    CACHE.initialized = true // Marcar como inicializado para evitar bucles
    registrarLog('error', 'Error inicializando', { error: error.message })
  }
}

// Refrescar caché específico en segundo plano
function refreshCache(type) {
  setTimeout(async () => {
    try {
      switch (type) {
        case 'horas':
          const horasRes = await dbQuery('SELECT * FROM horas_trabajo ORDER BY fecha DESC, id DESC LIMIT 1000')
          if (horasRes.success) CACHE.horas = horasRes.rows
          break
        case 'avisos':
          const avisosRes = await dbQuery('SELECT * FROM avisos_trabajo ORDER BY id DESC')
          if (avisosRes.success) CACHE.avisos = avisosRes.rows
          break
        case 'obras':
          const obrasRes = await dbQuery('SELECT * FROM obras_trabajo ORDER BY id DESC')
          if (obrasRes.success) CACHE.obras = obrasRes.rows
          break
        case 'mantenimientos':
          const mantRes = await dbQuery('SELECT * FROM mantenimientos_trabajo ORDER BY id DESC')
          if (mantRes.success) CACHE.mantenimientos = mantRes.rows
          break
        case 'usuarios':
          const usersRes = await dbQuery('SELECT * FROM usuarios_horas WHERE activo = true ORDER BY id')
          if (usersRes.success && usersRes.rows.length > 0) {
            CACHE.usuarios = usersRes.rows.map(u => ({
              id: u.id, email: u.email, nombre: u.nombre, role: u.role, password: u.password, activo: u.activo
            }))
          }
          break
        case 'config':
          const configRes = await dbQuery("SELECT valor FROM configuracion_horas WHERE clave = 'general'")
          if (configRes.success && configRes.rows.length > 0) {
            CACHE.configuracion = { ...DEFAULT_CONFIG, ...configRes.rows[0].valor }
          }
          break
      }
      CACHE.lastSync[type] = Date.now()
    } catch (err) {
      console.error(`Error refreshing ${type}:`, err.message)
    }
  }, 100)
}

// Iniciar carga en segundo plano
initializeCache()

// ===== MIDDLEWARES =====
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'Token required' })
  try {
    req.user = jwt.verify(token, JWT_SECRET)
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

// ===== LOGS ENDPOINTS =====
app.get('/logs', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  const tipo = req.query.tipo
  let logs = logsEnMemoria
  if (tipo && tipo !== 'all') logs = logs.filter(l => l.tipo === tipo)
  res.json(logs.slice(0, parseInt(req.query.limit) || 100))
})

app.get('/logs/stats', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  const hace24h = Date.now() - (24 * 60 * 60 * 1000)
  const logsRecientes = logsEnMemoria.filter(l => new Date(l.fecha).getTime() > hace24h)
  res.json({
    por_tipo: ['success', 'error', 'warning', 'info'].map(tipo => ({
      tipo,
      cantidad: logsRecientes.filter(l => l.tipo === tipo).length
    })),
    total: logsEnMemoria.length
  })
})

app.delete('/logs', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  logsEnMemoria.length = 0
  res.json({ message: 'Logs limpiados' })
})

// ===== CONFIG PÚBLICO (ULTRA RÁPIDO) =====
app.get('/config/public', (req, res) => {
  res.json({
    bienvenida: CACHE.configuracion?.bienvenida || DEFAULT_CONFIG.bienvenida,
    empresa: {
      nombre: CACHE.configuracion?.empresa?.nombre || DEFAULT_CONFIG.empresa.nombre,
      logo: CACHE.configuracion?.empresa?.logo || null
    }
  })
})

// ===== AUTH ENDPOINTS =====
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body
  const usuario = CACHE.usuarios.find(u => u.email === email)
  
  if (!usuario || !bcrypt.compareSync(password, usuario.password)) {
    registrarLog('warning', 'Login fallido', { email })
    return res.status(401).json({ error: 'Credenciales inválidas' })
  }
  
  const token = jwt.sign(
    { id: usuario.id, email: usuario.email, role: usuario.role, nombre: usuario.nombre },
    JWT_SECRET,
    { expiresIn: '24h' }
  )
  
  registrarLog('success', 'Login exitoso', { email }, email)
  res.json({
    token,
    user: { id: usuario.id, email: usuario.email, nombre: usuario.nombre, role: usuario.role }
  })
})

app.get('/auth/me', verifyToken, (req, res) => {
  const usuario = CACHE.usuarios.find(u => u.id === req.user.id)
  if (!usuario) return res.status(404).json({ error: 'User not found' })
  res.json({ id: usuario.id, email: usuario.email, nombre: usuario.nombre, role: usuario.role })
})

// ===== HORAS ENDPOINTS (DESDE CACHÉ) =====
app.get('/horas', verifyToken, async (req, res) => {
  // Si el caché está vacío, forzar recarga desde BD con reintentos
  if (CACHE.horas.length === 0) {
    console.log('⚠️ Caché horas vacío, intentando recargar...')
    
    for (let intento = 1; intento <= 3; intento++) {
      console.log(`📡 Intento ${intento}/3 cargando horas...`)
      const horasRes = await dbQuery('SELECT * FROM horas_trabajo ORDER BY fecha DESC, id DESC LIMIT 1000', [], 20000)
      
      if (horasRes.success && horasRes.rows.length > 0) {
        CACHE.horas = horasRes.rows
        console.log(`✅ Recargadas ${horasRes.rows.length} horas desde BD`)
        break
      } else if (horasRes.success && horasRes.rows.length === 0) {
        // BD accesible pero sin datos - es válido
        console.log('ℹ️ BD accesible, pero no hay horas registradas')
        break
      }
      
      // Esperar antes de reintentar
      if (intento < 3) {
        await new Promise(r => setTimeout(r, 1500))
      }
    }
  }
  
  let horas = CACHE.horas
  if (req.user.role !== 'admin' && req.user.role !== 'supervisor') {
    horas = horas.filter(h => h.usuario_id === req.user.id)
  }
  res.json(horas)
})

app.post('/horas', verifyToken, async (req, res) => {
  const { fecha, tipo_trabajo, numero_aviso, horas: cant_horas, descripcion } = req.body
  
  if (!fecha || !tipo_trabajo || !numero_aviso || cant_horas === undefined) {
    return res.status(400).json({ error: 'Campos requeridos' })
  }
  
  const result = await dbQuery(
    'INSERT INTO horas_trabajo (usuario_id, fecha, tipo_trabajo, numero_aviso, horas, descripcion) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
    [req.user.id, fecha, tipo_trabajo, numero_aviso, parseFloat(cant_horas), descripcion || '']
  )
  
  if (result.success && result.rows.length > 0) {
    // Actualizar caché inmediatamente
    CACHE.horas.unshift(result.rows[0])
    registrarLog('success', 'Horas registradas', { fecha, horas: cant_horas }, req.user.email)
    res.status(201).json(result.rows[0])
  } else {
    res.status(500).json({ error: result.error || 'Error al guardar' })
  }
})

app.put('/horas/:id', verifyToken, async (req, res) => {
  const horaId = parseInt(req.params.id)
  const { fecha, tipo_trabajo, numero_aviso, horas: cant_horas, descripcion, estado } = req.body
  
  const existing = CACHE.horas.find(h => h.id === horaId)
  if (!existing) return res.status(404).json({ error: 'No encontrado' })
  
  if (existing.usuario_id !== req.user.id && req.user.role === 'operario') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const result = await dbQuery(
    'UPDATE horas_trabajo SET fecha=$1, tipo_trabajo=$2, numero_aviso=$3, horas=$4, descripcion=$5, estado=$6 WHERE id=$7 RETURNING *',
    [fecha, tipo_trabajo, numero_aviso, parseFloat(cant_horas), descripcion, estado || 'pendiente', horaId]
  )
  
  if (result.success && result.rows.length > 0) {
    // Actualizar caché
    const idx = CACHE.horas.findIndex(h => h.id === horaId)
    if (idx !== -1) CACHE.horas[idx] = result.rows[0]
    res.json(result.rows[0])
  } else {
    res.status(500).json({ error: 'Error al actualizar' })
  }
})

app.delete('/horas/:id', verifyToken, async (req, res) => {
  const horaId = parseInt(req.params.id)
  
  const existing = CACHE.horas.find(h => h.id === horaId)
  if (!existing) return res.status(404).json({ error: 'No encontrado' })
  
  if (existing.usuario_id !== req.user.id && req.user.role === 'operario') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  // Eliminar de caché inmediatamente
  CACHE.horas = CACHE.horas.filter(h => h.id !== horaId)
  
  // Eliminar de DB en segundo plano
  dbWriteAsync('DELETE FROM horas_trabajo WHERE id=$1', [horaId])
  
  registrarLog('warning', 'Horas eliminadas', { id: horaId }, req.user.email)
  res.json({ message: 'Eliminado' })
})

app.put('/horas/:id/validar', verifyToken, (req, res) => {
  if (req.user.role === 'operario') return res.status(403).json({ error: 'No autorizado' })
  
  const horaId = parseInt(req.params.id)
  const { estado } = req.body
  const nuevoEstado = estado === 'validado' ? 'validado' : 'rechazado'
  
  // Actualizar caché inmediatamente
  const idx = CACHE.horas.findIndex(h => h.id === horaId)
  if (idx === -1) return res.status(404).json({ error: 'No encontrado' })
  
  CACHE.horas[idx] = { ...CACHE.horas[idx], estado: nuevoEstado }
  
  // Actualizar DB en segundo plano
  dbWriteAsync('UPDATE horas_trabajo SET estado = $1 WHERE id = $2', [nuevoEstado, horaId])
  
  registrarLog('info', `Horas ${nuevoEstado}`, { id: horaId }, req.user.email)
  res.json(CACHE.horas[idx])
})

// ===== BORRADO MASIVO =====
app.post('/horas/borrar-masivo', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo admin' })
  
  const { usuario_ids, fecha_desde, fecha_hasta, borrar_todo } = req.body
  
  let query = 'DELETE FROM horas_trabajo WHERE 1=1'
  const params = []
  let paramIndex = 1
  
  if (!borrar_todo) {
    if (usuario_ids?.length > 0) {
      query += ` AND usuario_id = ANY($${paramIndex}::int[])`
      params.push(usuario_ids)
      paramIndex++
    }
    if (fecha_desde) {
      query += ` AND fecha >= $${paramIndex}`
      params.push(fecha_desde)
      paramIndex++
    }
    if (fecha_hasta) {
      query += ` AND fecha <= $${paramIndex}`
      params.push(fecha_hasta)
      paramIndex++
    }
  }
  
  // Contar antes de borrar
  const countQuery = query.replace('DELETE FROM', 'SELECT COUNT(*) as count FROM')
  const countResult = await dbQuery(countQuery, params)
  const count = countResult.success ? parseInt(countResult.rows[0]?.count || 0) : 0
  
  if (count === 0) return res.json({ message: 'No hay registros', deleted: 0 })
  
  const result = await dbQuery(query, params)
  
  if (result.success) {
    // Actualizar caché
    refreshCache('horas')
    registrarLog('warning', `Borrado masivo: ${count} registros`, { usuario_ids, fecha_desde, fecha_hasta }, req.user.email)
    res.json({ message: `Eliminados ${count} registros`, deleted: count })
  } else {
    res.status(500).json({ error: 'Error al borrar' })
  }
})

app.get('/horas/resumen-borrado', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  // Calcular desde caché para respuesta instantánea
  const porUsuario = {}
  CACHE.horas.forEach(h => {
    if (!porUsuario[h.usuario_id]) {
      const user = CACHE.usuarios.find(u => u.id === h.usuario_id)
      porUsuario[h.usuario_id] = {
        usuario_id: h.usuario_id,
        nombre: user?.nombre || `Usuario ${h.usuario_id}`,
        email: user?.email || '-',
        total_registros: 0,
        total_horas: 0
      }
    }
    porUsuario[h.usuario_id].total_registros++
    porUsuario[h.usuario_id].total_horas += parseFloat(h.horas) || 0
  })
  
  res.json({
    por_usuario: Object.values(porUsuario),
    total: {
      registros: CACHE.horas.length,
      horas: CACHE.horas.reduce((sum, h) => sum + (parseFloat(h.horas) || 0), 0)
    }
  })
})

// ===== AVISOS (DESDE CACHÉ) =====
app.get('/avisos', verifyToken, (req, res) => {
  res.json(CACHE.avisos)
})

app.get('/avisos/activos', verifyToken, (req, res) => {
  res.json(CACHE.avisos.filter(a => a.estado === 'en_curso'))
})

app.post('/avisos', verifyToken, verifyAdmin, async (req, res) => {
  const { numero, cliente, descripcion, estado, fecha, alertas_email } = req.body
  if (!numero || !cliente || !descripcion || !fecha) {
    return res.status(400).json({ error: 'Campos requeridos' })
  }
  
  const result = await dbQuery(
    'INSERT INTO avisos_trabajo (numero, cliente, descripcion, estado, fecha, alertas_email) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
    [numero, cliente, descripcion, estado || 'en_curso', fecha, JSON.stringify(alertas_email || [])]
  )
  
  if (result.success && result.rows.length > 0) {
    CACHE.avisos.unshift(result.rows[0])
    registrarLog('success', 'Aviso creado', { numero }, req.user.email)
    res.status(201).json(result.rows[0])
  } else {
    res.status(500).json({ error: 'Error al crear' })
  }
})

app.put('/avisos/:id', verifyToken, verifyAdmin, async (req, res) => {
  const id = parseInt(req.params.id)
  const { numero, cliente, descripcion, estado, fecha, alertas_email } = req.body
  
  const result = await dbQuery(
    'UPDATE avisos_trabajo SET numero=$1, cliente=$2, descripcion=$3, estado=$4, fecha=$5, alertas_email=$6 WHERE id=$7 RETURNING *',
    [numero, cliente, descripcion, estado, fecha, JSON.stringify(alertas_email || []), id]
  )
  
  if (result.success && result.rows.length > 0) {
    const idx = CACHE.avisos.findIndex(a => a.id === id)
    if (idx !== -1) CACHE.avisos[idx] = result.rows[0]
    res.json(result.rows[0])
  } else {
    res.status(404).json({ error: 'No encontrado' })
  }
})

app.delete('/avisos/:id', verifyToken, verifyAdmin, (req, res) => {
  const id = parseInt(req.params.id)
  CACHE.avisos = CACHE.avisos.filter(a => a.id !== id)
  dbWriteAsync('DELETE FROM avisos_trabajo WHERE id = $1', [id])
  registrarLog('warning', 'Aviso eliminado', { id }, req.user.email)
  res.json({ message: 'Eliminado' })
})

// ===== OBRAS (DESDE CACHÉ) =====
app.get('/obras', verifyToken, (req, res) => {
  res.json(CACHE.obras)
})

app.get('/obras/activas', verifyToken, (req, res) => {
  res.json(CACHE.obras.filter(o => o.estado === 'en_curso'))
})

app.post('/obras', verifyToken, verifyAdmin, async (req, res) => {
  const { numero, cliente, descripcion, estado, fecha, fecha_fin_estimada, alertas_email } = req.body
  if (!numero || !cliente || !descripcion || !fecha) {
    return res.status(400).json({ error: 'Campos requeridos' })
  }
  
  const result = await dbQuery(
    'INSERT INTO obras_trabajo (numero, cliente, descripcion, estado, fecha, fecha_fin_estimada, alertas_email) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
    [numero, cliente, descripcion, estado || 'en_curso', fecha, fecha_fin_estimada || null, JSON.stringify(alertas_email || [])]
  )
  
  if (result.success && result.rows.length > 0) {
    CACHE.obras.unshift(result.rows[0])
    registrarLog('success', 'Obra creada', { numero }, req.user.email)
    res.status(201).json(result.rows[0])
  } else {
    res.status(500).json({ error: 'Error al crear' })
  }
})

app.put('/obras/:id', verifyToken, verifyAdmin, async (req, res) => {
  const id = parseInt(req.params.id)
  const { numero, cliente, descripcion, estado, fecha, fecha_fin_estimada, alertas_email } = req.body
  
  const result = await dbQuery(
    'UPDATE obras_trabajo SET numero=$1, cliente=$2, descripcion=$3, estado=$4, fecha=$5, fecha_fin_estimada=$6, alertas_email=$7 WHERE id=$8 RETURNING *',
    [numero, cliente, descripcion, estado, fecha, fecha_fin_estimada, JSON.stringify(alertas_email || []), id]
  )
  
  if (result.success && result.rows.length > 0) {
    const idx = CACHE.obras.findIndex(o => o.id === id)
    if (idx !== -1) CACHE.obras[idx] = result.rows[0]
    res.json(result.rows[0])
  } else {
    res.status(404).json({ error: 'No encontrado' })
  }
})

app.delete('/obras/:id', verifyToken, verifyAdmin, (req, res) => {
  const id = parseInt(req.params.id)
  CACHE.obras = CACHE.obras.filter(o => o.id !== id)
  dbWriteAsync('DELETE FROM obras_trabajo WHERE id = $1', [id])
  registrarLog('warning', 'Obra eliminada', { id }, req.user.email)
  res.json({ message: 'Eliminado' })
})

// ===== MANTENIMIENTOS (DESDE CACHÉ) =====
app.get('/mantenimientos', verifyToken, (req, res) => {
  res.json(CACHE.mantenimientos)
})

app.get('/mantenimientos/activos', verifyToken, (req, res) => {
  res.json(CACHE.mantenimientos.filter(m => m.estado === 'activo'))
})

app.post('/mantenimientos', verifyToken, verifyAdmin, async (req, res) => {
  const { descripcion, tipo_alerta, cliente, estado, primera_alerta, alertas_email } = req.body
  if (!descripcion || !tipo_alerta || !cliente || !primera_alerta) {
    return res.status(400).json({ error: 'Campos requeridos' })
  }
  
  const proxima_alerta = calcularProximaAlerta(tipo_alerta, primera_alerta)
  
  const result = await dbQuery(
    'INSERT INTO mantenimientos_trabajo (descripcion, cliente, tipo_alerta, primera_alerta, proxima_alerta, estado, alertas_email) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
    [descripcion, cliente, tipo_alerta, primera_alerta, proxima_alerta, estado || 'activo', JSON.stringify(alertas_email || [])]
  )
  
  if (result.success && result.rows.length > 0) {
    CACHE.mantenimientos.unshift(result.rows[0])
    registrarLog('success', 'Mantenimiento creado', { cliente }, req.user.email)
    res.status(201).json(result.rows[0])
  } else {
    res.status(500).json({ error: 'Error al crear' })
  }
})

app.put('/mantenimientos/:id', verifyToken, verifyAdmin, async (req, res) => {
  const id = parseInt(req.params.id)
  const { descripcion, tipo_alerta, cliente, estado, primera_alerta, alertas_email } = req.body
  
  const proxima_alerta = tipo_alerta && primera_alerta ? calcularProximaAlerta(tipo_alerta, primera_alerta) : null
  
  const result = await dbQuery(
    'UPDATE mantenimientos_trabajo SET descripcion=$1, cliente=$2, tipo_alerta=$3, primera_alerta=$4, proxima_alerta=COALESCE($5, proxima_alerta), estado=$6, alertas_email=$7 WHERE id=$8 RETURNING *',
    [descripcion, cliente, tipo_alerta, primera_alerta, proxima_alerta, estado, JSON.stringify(alertas_email || []), id]
  )
  
  if (result.success && result.rows.length > 0) {
    const idx = CACHE.mantenimientos.findIndex(m => m.id === id)
    if (idx !== -1) CACHE.mantenimientos[idx] = result.rows[0]
    res.json(result.rows[0])
  } else {
    res.status(404).json({ error: 'No encontrado' })
  }
})

app.delete('/mantenimientos/:id', verifyToken, verifyAdmin, (req, res) => {
  const id = parseInt(req.params.id)
  CACHE.mantenimientos = CACHE.mantenimientos.filter(m => m.id !== id)
  dbWriteAsync('DELETE FROM mantenimientos_trabajo WHERE id = $1', [id])
  registrarLog('warning', 'Mantenimiento eliminado', { id }, req.user.email)
  res.json({ message: 'Eliminado' })
})

// ===== USUARIOS (DESDE CACHÉ) =====
app.get('/usuarios', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  res.json(CACHE.usuarios.map(u => ({ id: u.id, email: u.email, nombre: u.nombre, role: u.role, activo: u.activo !== false })))
})

app.post('/usuarios', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const { email, nombre, role, password } = req.body
  if (!email || !nombre || !role) return res.status(400).json({ error: 'Campos requeridos' })
  
  const hashedPassword = bcrypt.hashSync(password || 'TempPassword2025!', 10)
  
  const result = await dbQuery(
    'INSERT INTO usuarios_horas (email, nombre, role, password) VALUES ($1, $2, $3, $4) RETURNING id, email, nombre, role, activo',
    [email, nombre, role, hashedPassword]
  )
  
  if (result.success && result.rows.length > 0) {
    CACHE.usuarios.push({ ...result.rows[0], password: hashedPassword })
    registrarLog('success', 'Usuario creado', { email }, req.user.email)
    res.status(201).json(result.rows[0])
  } else {
    res.status(500).json({ error: result.error || 'Error al crear' })
  }
})

app.put('/usuarios/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const userId = parseInt(req.params.id)
  const { email, nombre, role, password } = req.body
  
  let query, params
  if (password) {
    const hashedPassword = bcrypt.hashSync(password, 10)
    query = 'UPDATE usuarios_horas SET email=$1, nombre=$2, role=$3, password=$4 WHERE id=$5 RETURNING id, email, nombre, role, activo'
    params = [email, nombre, role, hashedPassword, userId]
  } else {
    query = 'UPDATE usuarios_horas SET email=$1, nombre=$2, role=$3 WHERE id=$4 RETURNING id, email, nombre, role, activo'
    params = [email, nombre, role, userId]
  }
  
  const result = await dbQuery(query, params)
  
  if (result.success && result.rows.length > 0) {
    const idx = CACHE.usuarios.findIndex(u => u.id === userId)
    if (idx !== -1) {
      CACHE.usuarios[idx] = { ...CACHE.usuarios[idx], email, nombre, role }
      if (password) CACHE.usuarios[idx].password = bcrypt.hashSync(password, 10)
    }
    registrarLog('info', 'Usuario actualizado', { id: userId }, req.user.email)
    res.json(result.rows[0])
  } else {
    res.status(404).json({ error: 'No encontrado' })
  }
})

app.delete('/usuarios/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const userId = parseInt(req.params.id)
  CACHE.usuarios = CACHE.usuarios.filter(u => u.id !== userId)
  dbWriteAsync('UPDATE usuarios_horas SET activo = false WHERE id = $1', [userId])
  registrarLog('warning', 'Usuario eliminado', { id: userId }, req.user.email)
  res.json({ message: 'Eliminado' })
})

// ===== ROLES (DESDE CACHÉ) =====
app.get('/roles', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  res.json(CACHE.roles)
})

app.put('/roles/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const roleId = parseInt(req.params.id)
  const { permisos } = req.body
  
  if (!Array.isArray(permisos)) return res.status(400).json({ error: 'permisos debe ser array' })
  
  // Actualizar caché inmediatamente
  const idx = CACHE.roles.findIndex(r => r.id === roleId)
  if (idx === -1) return res.status(404).json({ error: 'No encontrado' })
  
  CACHE.roles[idx] = { ...CACHE.roles[idx], permisos }
  
  // Guardar en DB en segundo plano
  dbWriteAsync('UPDATE roles_horas SET permisos = $1 WHERE id = $2', [JSON.stringify(permisos), roleId])
  
  registrarLog('info', 'Permisos actualizados', { roleId }, req.user.email)
  res.json(CACHE.roles[idx])
})

app.post('/roles', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const { nombre, permisos } = req.body
  if (!nombre) return res.status(400).json({ error: 'Nombre requerido' })
  
  const nombreNorm = nombre.toLowerCase().trim()
  
  if (CACHE.roles.some(r => r.nombre === nombreNorm)) {
    return res.status(400).json({ error: 'Ya existe' })
  }
  
  const result = await dbQuery(
    'INSERT INTO roles_horas (nombre, permisos) VALUES ($1, $2) RETURNING *',
    [nombreNorm, JSON.stringify(permisos || [])]
  )
  
  if (result.success && result.rows.length > 0) {
    const newRole = { id: result.rows[0].id, nombre: nombreNorm, permisos: permisos || [] }
    CACHE.roles.push(newRole)
    registrarLog('success', 'Rol creado', { nombre: nombreNorm }, req.user.email)
    res.status(201).json(newRole)
  } else {
    res.status(500).json({ error: 'Error al crear' })
  }
})

app.delete('/roles/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const roleId = parseInt(req.params.id)
  const role = CACHE.roles.find(r => r.id === roleId)
  
  if (role && ['admin', 'supervisor', 'operario'].includes(role.nombre)) {
    return res.status(400).json({ error: 'No se pueden eliminar roles del sistema' })
  }
  
  CACHE.roles = CACHE.roles.filter(r => r.id !== roleId)
  dbWriteAsync('DELETE FROM roles_horas WHERE id = $1', [roleId])
  registrarLog('warning', 'Rol eliminado', { id: roleId }, req.user.email)
  res.json({ message: 'Eliminado' })
})

// ===== CONFIGURACIÓN (DESDE CACHÉ) =====
app.get('/configuracion', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'supervisor') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  // Si SMTP está vacío, intentar recargar desde BD
  if (!CACHE.configuracion?.smtp?.host && CACHE.initialized) {
    console.log('⚠️ Config SMTP vacía, recargando desde BD...')
    const configRes = await dbQuery("SELECT valor FROM configuracion_horas WHERE clave = 'general'", [], 15000)
    if (configRes.success && configRes.rows.length > 0) {
      CACHE.configuracion = { ...DEFAULT_CONFIG, ...configRes.rows[0].valor }
      console.log('✅ Configuración recargada desde BD')
    }
  }
  
  res.json(CACHE.configuracion)
})

app.put('/configuracion/empresa', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const { nombre, logo, color_primario, color_secundario } = req.body
  
  // Actualizar caché inmediatamente
  if (!CACHE.configuracion.empresa) CACHE.configuracion.empresa = {}
  if (nombre !== undefined) CACHE.configuracion.empresa.nombre = nombre
  if (logo !== undefined) CACHE.configuracion.empresa.logo = logo
  if (color_primario !== undefined) CACHE.configuracion.empresa.color_primario = color_primario
  if (color_secundario !== undefined) CACHE.configuracion.empresa.color_secundario = color_secundario
  
  // Guardar en DB en segundo plano
  saveConfigAsync()
  
  registrarLog('info', 'Config empresa actualizada', { nombre }, req.user.email)
  res.json(CACHE.configuracion.empresa)
})

app.put('/configuracion/bienvenida', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const { titulo, subtitulo } = req.body
  
  if (!CACHE.configuracion.bienvenida) CACHE.configuracion.bienvenida = {}
  if (titulo !== undefined) CACHE.configuracion.bienvenida.titulo = titulo
  if (subtitulo !== undefined) CACHE.configuracion.bienvenida.subtitulo = subtitulo
  
  saveConfigAsync()
  
  registrarLog('info', 'Config bienvenida actualizada', {}, req.user.email)
  res.json(CACHE.configuracion.bienvenida)
})

app.put('/configuracion/idioma', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const { idioma_principal, traducciones } = req.body
  
  if (!CACHE.configuracion.idioma) CACHE.configuracion.idioma = {}
  if (idioma_principal !== undefined) CACHE.configuracion.idioma.idioma_principal = idioma_principal
  if (traducciones !== undefined) CACHE.configuracion.idioma.traducciones = traducciones
  
  saveConfigAsync()
  
  registrarLog('info', 'Config idioma actualizada', { idioma: idioma_principal }, req.user.email)
  res.json(CACHE.configuracion.idioma)
})

app.put('/configuracion/smtp', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const { host, puerto, usuario, contraseña } = req.body
  
  if (!CACHE.configuracion.smtp) CACHE.configuracion.smtp = {}
  if (host !== undefined) CACHE.configuracion.smtp.host = host
  if (puerto !== undefined) CACHE.configuracion.smtp.puerto = puerto
  if (usuario !== undefined) CACHE.configuracion.smtp.usuario = usuario
  if (contraseña !== undefined) CACHE.configuracion.smtp.contraseña = contraseña
  
  // Guardar en DB con confirmación (esperamos respuesta)
  const result = await saveConfigSync()
  
  if (result.success) {
    registrarLog('success', 'Config SMTP guardada en BD', { host }, req.user.email)
  } else {
    registrarLog('warning', 'Config SMTP en caché (BD lenta)', { host, error: result.error }, req.user.email)
  }
  
  res.json({ ...CACHE.configuracion.smtp, saved: result.success })
})

function saveConfigAsync() {
  dbWriteAsync(
    "INSERT INTO configuracion_horas (clave, valor) VALUES ($1, $2) ON CONFLICT (clave) DO UPDATE SET valor = $2",
    ['general', JSON.stringify(CACHE.configuracion)]
  )
}

// Guardar config con confirmación (para datos críticos como SMTP)
async function saveConfigSync() {
  const result = await dbQuery(
    "INSERT INTO configuracion_horas (clave, valor) VALUES ($1, $2) ON CONFLICT (clave) DO UPDATE SET valor = $2",
    ['general', JSON.stringify(CACHE.configuracion)],
    15000 // 15 segundos timeout
  )
  return result
}

// ===== SMTP TEST =====
app.post('/smtp/test', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  const { host, puerto, usuario, contraseña, email_destino } = req.body
  
  if (!host || !usuario || !contraseña || !email_destino) {
    return res.status(400).json({ error: 'Faltan datos' })
  }
  
  try {
    const nodemailer = require('nodemailer')
    
    const transporter = nodemailer.createTransport({
      host,
      port: parseInt(puerto) || 587,
      secure: parseInt(puerto) === 465,
      auth: { user: usuario, pass: contraseña },
      tls: { rejectUnauthorized: false },
      connectionTimeout: 10000,
      greetingTimeout: 10000
    })
    
    await transporter.verify()
    
    await transporter.sendMail({
      from: `"GrupLomi" <${usuario}>`,
      to: email_destino,
      subject: '✅ Prueba SMTP - GrupLomi Horas',
      html: '<h1 style="color:#10b981">✅ Configuración SMTP Correcta</h1><p>Este es un email de prueba.</p>'
    })
    
    registrarLog('success', 'Prueba SMTP exitosa', { host }, req.user.email)
    res.json({ success: true, message: 'Email enviado' })
    
  } catch (error) {
    let errorMsg = error.message
    if (error.code === 'EAUTH') errorMsg = 'Error de autenticación'
    else if (error.code === 'ESOCKET' || error.code === 'ECONNECTION') errorMsg = 'No se pudo conectar'
    else if (error.code === 'ETIMEDOUT') errorMsg = 'Tiempo agotado'
    
    registrarLog('error', 'Prueba SMTP fallida', { error: errorMsg }, req.user.email)
    res.status(500).json({ error: errorMsg })
  }
})

// ===== TICKET SOPORTE =====
app.post('/ticket/enviar', verifyToken, async (req, res) => {
  const { asunto, descripcion, tipo, adjuntos, usuario } = req.body
  
  if (!asunto || !descripcion) {
    return res.status(400).json({ error: 'Asunto y descripción son requeridos' })
  }
  
  // Si SMTP no está en caché, intentar recargar desde BD
  if (!CACHE.configuracion?.smtp?.host) {
    console.log('⚠️ SMTP no en caché, recargando config desde BD...')
    const configRes = await dbQuery("SELECT valor FROM configuracion_horas WHERE clave = 'general'", [], 15000)
    if (configRes.success && configRes.rows.length > 0) {
      CACHE.configuracion = { ...DEFAULT_CONFIG, ...configRes.rows[0].valor }
      console.log('✅ Config recargada para enviar ticket')
    }
  }
  
  // Obtener configuración SMTP del caché
  const smtp = CACHE.configuracion?.smtp
  if (!smtp?.host || !smtp?.usuario || !smtp?.contraseña) {
    return res.status(400).json({ error: 'SMTP no configurado. Contacta con el administrador.' })
  }
  
  try {
    const nodemailer = require('nodemailer')
    
    const transporter = nodemailer.createTransport({
      host: smtp.host,
      port: parseInt(smtp.puerto) || 587,
      secure: parseInt(smtp.puerto) === 465,
      auth: { user: smtp.usuario, pass: smtp.contraseña },
      tls: { rejectUnauthorized: false },
      connectionTimeout: 15000,
      greetingTimeout: 15000
    })
    
    // Preparar adjuntos
    const attachments = (adjuntos || []).map((adj, index) => {
      // Extraer base64 data del formato data:image/xxx;base64,xxxxx
      const matches = adj.data.match(/^data:(.+);base64,(.+)$/)
      if (matches) {
        return {
          filename: adj.nombre || `adjunto_${index + 1}.jpg`,
          content: matches[2],
          encoding: 'base64',
          contentType: matches[1]
        }
      }
      return null
    }).filter(Boolean)
    
    // Iconos para tipos
    const tipoIcons = {
      'error': '🐛',
      'mejora': '💡',
      'consulta': '❓',
      'otro': '📝'
    }
    
    const tipoLabels = {
      'error': 'Error / Bug',
      'mejora': 'Sugerencia de mejora',
      'consulta': 'Consulta',
      'otro': 'Otro'
    }
    
    // Construir HTML del email
    const htmlContent = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #0071e3, #5856d6); padding: 20px; border-radius: 12px 12px 0 0; text-align: center;">
          <h1 style="color: white; margin: 0; font-size: 24px;">🎫 Nuevo Ticket de Soporte</h1>
        </div>
        
        <div style="background: #f5f5f7; padding: 25px; border-radius: 0 0 12px 12px;">
          <div style="background: white; padding: 20px; border-radius: 10px; margin-bottom: 15px;">
            <p style="margin: 0 0 10px 0; color: #666;"><strong>Tipo:</strong></p>
            <p style="margin: 0; font-size: 16px;">${tipoIcons[tipo] || '📝'} ${tipoLabels[tipo] || tipo}</p>
          </div>
          
          <div style="background: white; padding: 20px; border-radius: 10px; margin-bottom: 15px;">
            <p style="margin: 0 0 10px 0; color: #666;"><strong>Asunto:</strong></p>
            <p style="margin: 0; font-size: 18px; font-weight: 600;">${asunto}</p>
          </div>
          
          <div style="background: white; padding: 20px; border-radius: 10px; margin-bottom: 15px;">
            <p style="margin: 0 0 10px 0; color: #666;"><strong>Descripción:</strong></p>
            <p style="margin: 0; white-space: pre-wrap; line-height: 1.6;">${descripcion}</p>
          </div>
          
          <div style="background: white; padding: 20px; border-radius: 10px;">
            <p style="margin: 0 0 10px 0; color: #666;"><strong>Usuario:</strong></p>
            <p style="margin: 0;">👤 ${usuario?.nombre || 'N/A'}</p>
            <p style="margin: 5px 0 0 0; color: #666;">📧 ${usuario?.email || 'N/A'}</p>
            <p style="margin: 5px 0 0 0; color: #666;">🔑 Rol: ${usuario?.role || 'N/A'}</p>
          </div>
          
          ${attachments.length > 0 ? `
            <div style="background: white; padding: 20px; border-radius: 10px; margin-top: 15px;">
              <p style="margin: 0 0 10px 0; color: #666;"><strong>📎 Adjuntos:</strong> ${attachments.length} archivo(s)</p>
            </div>
          ` : ''}
          
          <p style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
            Ticket enviado desde GrupLomi Horas v4.1<br>
            ${new Date().toLocaleString('es-ES')}
          </p>
        </div>
      </div>
    `
    
    await transporter.sendMail({
      from: `"GrupLomi Horas - Ticket" <${smtp.usuario}>`,
      to: 'suport@gruplomi.com',
      replyTo: usuario?.email || smtp.usuario,
      subject: `[Ticket] ${tipoIcons[tipo] || '📝'} ${asunto}`,
      html: htmlContent,
      attachments: attachments
    })
    
    registrarLog('success', 'Ticket enviado', { asunto, tipo }, req.user.email)
    res.json({ success: true, message: 'Ticket enviado correctamente' })
    
  } catch (error) {
    console.error('Error enviando ticket:', error)
    registrarLog('error', 'Error enviando ticket', { error: error.message }, req.user.email)
    res.status(500).json({ error: 'Error al enviar el ticket: ' + error.message })
  }
})

// ===== HEALTH =====
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '4.4',
    cache: {
      usuarios: CACHE.usuarios.length,
      horas: CACHE.horas.length,
      avisos: CACHE.avisos.length,
      obras: CACHE.obras.length,
      mantenimientos: CACHE.mantenimientos.length,
      initialized: CACHE.initialized,
      smtp_configured: !!(CACHE.configuracion?.smtp?.host && CACHE.configuracion?.smtp?.usuario)
    }
  })
})

// Forzar recarga de caché desde BD
app.post('/cache/reload', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'No autorizado' })
  
  console.log('🔄 Forzando recarga de caché...')
  
  try {
    const [configRes, usersRes, horasRes, avisosRes, obrasRes, mantRes] = await Promise.all([
      dbQuery("SELECT valor FROM configuracion_horas WHERE clave = 'general'", [], 15000),
      dbQuery('SELECT * FROM usuarios_horas WHERE activo = true ORDER BY id', [], 15000),
      dbQuery('SELECT * FROM horas_trabajo ORDER BY fecha DESC, id DESC LIMIT 1000', [], 15000),
      dbQuery('SELECT * FROM avisos_trabajo ORDER BY id DESC', [], 15000),
      dbQuery('SELECT * FROM obras_trabajo ORDER BY id DESC', [], 15000),
      dbQuery('SELECT * FROM mantenimientos_trabajo ORDER BY id DESC', [], 15000)
    ])
    
    const results = {
      config: configRes.success ? `✅ ${configRes.rows.length} registros` : `❌ ${configRes.error}`,
      usuarios: usersRes.success ? `✅ ${usersRes.rows.length} usuarios` : `❌ ${usersRes.error}`,
      horas: horasRes.success ? `✅ ${horasRes.rows.length} horas` : `❌ ${horasRes.error}`,
      avisos: avisosRes.success ? `✅ ${avisosRes.rows.length} avisos` : `❌ ${avisosRes.error}`,
      obras: obrasRes.success ? `✅ ${obrasRes.rows.length} obras` : `❌ ${obrasRes.error}`,
      mantenimientos: mantRes.success ? `✅ ${mantRes.rows.length} mant` : `❌ ${mantRes.error}`
    }
    
    // Actualizar caché con datos válidos
    if (configRes.success && configRes.rows.length > 0) {
      CACHE.configuracion = { ...DEFAULT_CONFIG, ...configRes.rows[0].valor }
    }
    if (usersRes.success && usersRes.rows.length > 0) {
      CACHE.usuarios = usersRes.rows.map(u => ({
        id: u.id, email: u.email, nombre: u.nombre, role: u.role, password: u.password, activo: u.activo
      }))
    }
    if (horasRes.success) CACHE.horas = horasRes.rows
    if (avisosRes.success) CACHE.avisos = avisosRes.rows
    if (obrasRes.success) CACHE.obras = obrasRes.rows
    if (mantRes.success) CACHE.mantenimientos = mantRes.rows
    
    CACHE.lastSync.all = Date.now()
    registrarLog('success', 'Caché recargado manualmente', results, req.user.email)
    
    res.json({
      success: true,
      results,
      cache_status: {
        usuarios: CACHE.usuarios.length,
        horas: CACHE.horas.length,
        avisos: CACHE.avisos.length,
        obras: CACHE.obras.length,
        mantenimientos: CACHE.mantenimientos.length,
        smtp_configured: !!(CACHE.configuracion?.smtp?.host)
      }
    })
  } catch (error) {
    registrarLog('error', 'Error recargando caché', { error: error.message }, req.user.email)
    res.status(500).json({ error: error.message })
  }
})

app.get('/test-db', async (req, res) => {
  const result = await dbQuery('SELECT 1 as test', [], 5000)
  res.json({ status: result.success ? 'ok' : 'error', latency: result.success ? 'fast' : 'slow' })
})

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' })
})

// ===== FUNCIONES AUXILIARES =====
function calcularProximaAlerta(tipo_alerta, fecha_base) {
  const proxima = new Date(fecha_base || new Date())
  switch(tipo_alerta) {
    case 'semanal': proxima.setDate(proxima.getDate() + 7); break
    case 'mensual': proxima.setMonth(proxima.getMonth() + 1); break
    case 'trimestral': proxima.setMonth(proxima.getMonth() + 3); break
    case 'anual': proxima.setFullYear(proxima.getFullYear() + 1); break
  }
  return proxima.toISOString().split('T')[0]
}

const PORT = process.env.PORT || 8000
app.listen(PORT, () => console.log(`🚀 Backend v4.4 on port ${PORT}`))

module.exports = app
