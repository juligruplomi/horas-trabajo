const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const fetch = require('node-fetch')

const app = express()

app.use(cors())
app.use(bodyParser.json())

const PROXY_URL = process.env.PROXY_URL || 'http://185.194.59.40:3001'
const PROXY_API_KEY = process.env.PROXY_API_KEY || 'GrupLomi2024ProxySecureKey_XyZ789'
const JWT_SECRET = process.env.JWT_SECRET_KEY || 'HorasTrabajo_JWT_Secret_2025'

// ===== FUNCIÓN PARA QUERIES A POSTGRESQL VIA PROXY =====
async function dbQuery(text, params = []) {
  try {
    const response = await fetch(`${PROXY_URL}/query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': PROXY_API_KEY
      },
      body: JSON.stringify({ text, params }),
      timeout: 25000
    })
    
    if (!response.ok) {
      const errorText = await response.text()
      console.error('Proxy error:', response.status, errorText)
      throw new Error(`Proxy error: ${response.status} - ${errorText}`)
    }
    
    const data = await response.json()
    
    if (data.error) {
      console.error('DB Error:', data.error)
      throw new Error(data.error)
    }
    
    return { rows: data.rows || [], success: true }
  } catch (error) {
    console.error('DB query error:', error.message)
    return { rows: [], success: false, error: error.message }
  }
}

// ===== INICIALIZAR TABLAS EN LA BASE DE DATOS =====
async function initDatabase() {
  try {
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS configuracion_horas (
        clave VARCHAR(100) PRIMARY KEY,
        valor JSONB NOT NULL
      )
    `)
    
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS usuarios_horas (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        nombre VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        password VARCHAR(255) NOT NULL,
        activo BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `)
    
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS horas_trabajo (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER,
        fecha DATE NOT NULL,
        tipo_trabajo VARCHAR(50) NOT NULL,
        numero_aviso VARCHAR(100),
        horas DECIMAL(4,2) NOT NULL,
        descripcion TEXT,
        estado VARCHAR(20) DEFAULT 'pendiente',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `)
    
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS avisos_trabajo (
        id SERIAL PRIMARY KEY,
        numero VARCHAR(50) UNIQUE NOT NULL,
        cliente VARCHAR(255) NOT NULL,
        descripcion TEXT,
        estado VARCHAR(20) DEFAULT 'en_curso',
        fecha DATE,
        alertas_email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `)
    
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS obras_trabajo (
        id SERIAL PRIMARY KEY,
        numero VARCHAR(50) UNIQUE NOT NULL,
        cliente VARCHAR(255) NOT NULL,
        descripcion TEXT,
        estado VARCHAR(20) DEFAULT 'en_curso',
        fecha DATE,
        fecha_fin_estimada DATE,
        alertas_email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `)
    
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS mantenimientos_trabajo (
        id SERIAL PRIMARY KEY,
        descripcion TEXT NOT NULL,
        cliente VARCHAR(255) NOT NULL,
        tipo_alerta VARCHAR(20),
        primera_alerta DATE,
        proxima_alerta DATE,
        estado VARCHAR(20) DEFAULT 'activo',
        alertas_email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `)
    
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS roles_horas (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(50) UNIQUE NOT NULL,
        permisos JSONB DEFAULT '[]'
      )
    `)
    
    console.log('✅ Database tables initialized')
    
    const configDB = await dbQuery("SELECT valor FROM configuracion_horas WHERE clave = 'general'")
    if (configDB.success && configDB.rows.length > 0) {
      configuracion = configDB.rows[0].valor
      console.log('✅ Configuration loaded from database')
    }
    
    await loadUsersFromDB()
    await loadRolesFromDB()
    
  } catch (error) {
    console.error('Database init error:', error)
  }
}

// ===== CARGAR USUARIOS DESDE DB =====
async function loadUsersFromDB() {
  try {
    const dbUsers = await dbQuery('SELECT * FROM usuarios_horas WHERE activo = true ORDER BY id')
    if (dbUsers.success && dbUsers.rows.length > 0) {
      usuarios = dbUsers.rows.map(u => ({
        id: u.id,
        email: u.email,
        nombre: u.nombre,
        role: u.role,
        password: u.password,
        activo: u.activo
      }))
      console.log(`✅ Loaded ${usuarios.length} users from database`)
    } else {
      console.log('📝 No users found, creating defaults...')
      for (const user of usuarios) {
        await dbQuery(
          'INSERT INTO usuarios_horas (email, nombre, role, password) VALUES ($1, $2, $3, $4) ON CONFLICT (email) DO NOTHING',
          [user.email, user.nombre, user.role, user.password]
        )
      }
      const reloaded = await dbQuery('SELECT * FROM usuarios_horas ORDER BY id')
      if (reloaded.success && reloaded.rows.length > 0) {
        usuarios = reloaded.rows.map(u => ({
          id: u.id,
          email: u.email,
          nombre: u.nombre,
          role: u.role,
          password: u.password,
          activo: u.activo !== false
        }))
      }
      console.log('✅ Default users created in database')
    }
  } catch (error) {
    console.error('Error loading users:', error)
  }
}

// ===== CARGAR ROLES DESDE DB =====
async function loadRolesFromDB() {
  try {
    const dbRoles = await dbQuery('SELECT * FROM roles_horas ORDER BY id')
    if (dbRoles.success && dbRoles.rows.length > 0) {
      roles = dbRoles.rows.map(r => ({
        id: r.id,
        nombre: r.nombre,
        permisos: r.permisos || []
      }))
      console.log(`✅ Loaded ${roles.length} roles from database`)
    } else {
      console.log('📝 No roles found, creating defaults...')
      for (const role of roles) {
        await dbQuery(
          'INSERT INTO roles_horas (nombre, permisos) VALUES ($1, $2) ON CONFLICT (nombre) DO NOTHING',
          [role.nombre, JSON.stringify(role.permisos)]
        )
      }
      const reloaded = await dbQuery('SELECT * FROM roles_horas ORDER BY id')
      if (reloaded.success && reloaded.rows.length > 0) {
        roles = reloaded.rows.map(r => ({
          id: r.id,
          nombre: r.nombre,
          permisos: r.permisos || []
        }))
      }
      console.log('✅ Default roles created in database')
    }
  } catch (error) {
    console.error('Error loading roles:', error)
  }
}

initDatabase()

// ===== DATOS EN MEMORIA (FALLBACK + DEFAULTS) =====
let usuarios = [
  { id: 1, email: 'admin@gruplomi.com', nombre: 'Admin', role: 'admin', password: bcrypt.hashSync('Admin2025!', 10) },
  { id: 2, email: 'supervisor@gruplomi.com', nombre: 'Supervisor', role: 'supervisor', password: bcrypt.hashSync('Sup2025!', 10) },
  { id: 3, email: 'juan@gruplomi.com', nombre: 'Juan Lopez', role: 'operario', password: bcrypt.hashSync('Juan2025!', 10) }
]

let roles = [
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

// ===== MIDDLEWARES =====
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

// ===== ENDPOINT PÚBLICO: CONFIGURACIÓN DE BIENVENIDA (SIN AUTH) =====
app.get('/config/public', async (req, res) => {
  try {
    const dbConfig = await dbQuery("SELECT valor FROM configuracion_horas WHERE clave = 'general'")
    if (dbConfig.success && dbConfig.rows.length > 0) {
      const config = dbConfig.rows[0].valor
      res.json({
        bienvenida: config.bienvenida || configuracion.bienvenida,
        empresa: {
          nombre: config.empresa?.nombre || configuracion.empresa.nombre,
          logo: config.empresa?.logo || configuracion.empresa.logo
        }
      })
    } else {
      res.json({
        bienvenida: configuracion.bienvenida,
        empresa: {
          nombre: configuracion.empresa.nombre,
          logo: configuracion.empresa.logo
        }
      })
    }
  } catch (error) {
    res.json({
      bienvenida: configuracion.bienvenida,
      empresa: {
        nombre: configuracion.empresa.nombre,
        logo: configuracion.empresa.logo
      }
    })
  }
})

// ===== AUTH ENDPOINTS =====
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body
  const usuario = usuarios.find(u => u.email === email)
  if (!usuario || !bcrypt.compareSync(password, usuario.password)) {
    return res.status(401).json({ error: 'Credenciales inválidas' })
  }
  const token = jwt.sign({ id: usuario.id, email: usuario.email, role: usuario.role, nombre: usuario.nombre }, JWT_SECRET, { expiresIn: '24h' })
  res.json({ token, user: { id: usuario.id, email: usuario.email, nombre: usuario.nombre, role: usuario.role } })
})

app.get('/auth/me', verifyToken, (req, res) => {
  const usuario = usuarios.find(u => u.id === req.user.id)
  if (!usuario) return res.status(404).json({ error: 'User not found' })
  res.json({ id: usuario.id, email: usuario.email, nombre: usuario.nombre, role: usuario.role })
})

// ===== HORAS ENDPOINTS (CON PERSISTENCIA) =====
app.get('/horas', verifyToken, async (req, res) => {
  try {
    let result
    if (req.user.role === 'admin' || req.user.role === 'supervisor') {
      result = await dbQuery('SELECT * FROM horas_trabajo ORDER BY fecha DESC, id DESC')
    } else {
      result = await dbQuery('SELECT * FROM horas_trabajo WHERE usuario_id = $1 ORDER BY fecha DESC', [req.user.id])
    }
    
    if (result.success) {
      res.json(result.rows)
    } else {
      res.json([])
    }
  } catch (error) {
    console.error('Error fetching horas:', error)
    res.json([])
  }
})

app.post('/horas', verifyToken, async (req, res) => {
  const { fecha, tipo_trabajo, numero_aviso, horas: cant_horas, descripcion } = req.body
  if (!fecha || !tipo_trabajo || !numero_aviso || !cant_horas) {
    return res.status(400).json({ error: 'Campos requeridos: fecha, tipo_trabajo, numero_aviso, horas' })
  }
  
  try {
    const result = await dbQuery(
      'INSERT INTO horas_trabajo (usuario_id, fecha, tipo_trabajo, numero_aviso, horas, descripcion) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [req.user.id, fecha, tipo_trabajo, parseFloat(cant_horas), numero_aviso, descripcion || '']
    )
    
    if (result.success && result.rows.length > 0) {
      res.status(201).json(result.rows[0])
    } else {
      res.status(500).json({ error: 'Error al guardar en la base de datos' })
    }
  } catch (error) {
    console.error('Error creating hora:', error)
    res.status(500).json({ error: 'Error al crear el registro' })
  }
})

app.put('/horas/:id', verifyToken, async (req, res) => {
  const horaId = parseInt(req.params.id)
  const { fecha, tipo_trabajo, numero_aviso, horas: cant_horas, descripcion, estado } = req.body
  
  try {
    const existing = await dbQuery('SELECT usuario_id FROM horas_trabajo WHERE id = $1', [horaId])
    if (!existing.success || existing.rows.length === 0) {
      return res.status(404).json({ error: 'Registro no encontrado' })
    }
    
    if (existing.rows[0].usuario_id !== req.user.id && req.user.role === 'operario') {
      return res.status(403).json({ error: 'No autorizado' })
    }
    
    const result = await dbQuery(
      'UPDATE horas_trabajo SET fecha=$1, tipo_trabajo=$2, numero_aviso=$3, horas=$4, descripcion=$5, estado=$6 WHERE id=$7 RETURNING *',
      [fecha, tipo_trabajo, numero_aviso, parseFloat(cant_horas), descripcion, estado || 'pendiente', horaId]
    )
    
    if (result.success && result.rows.length > 0) {
      res.json(result.rows[0])
    } else {
      res.status(500).json({ error: 'Error al actualizar' })
    }
  } catch (error) {
    console.error('Error updating hora:', error)
    res.status(500).json({ error: 'Error al actualizar' })
  }
})

app.delete('/horas/:id', verifyToken, async (req, res) => {
  const horaId = parseInt(req.params.id)
  
  try {
    const existing = await dbQuery('SELECT usuario_id FROM horas_trabajo WHERE id = $1', [horaId])
    if (!existing.success || existing.rows.length === 0) {
      return res.status(404).json({ error: 'Registro no encontrado' })
    }
    
    if (existing.rows[0].usuario_id !== req.user.id && req.user.role === 'operario') {
      return res.status(403).json({ error: 'No autorizado' })
    }
    
    await dbQuery('DELETE FROM horas_trabajo WHERE id=$1', [horaId])
    res.json({ message: 'Eliminado correctamente' })
  } catch (error) {
    console.error('Error deleting hora:', error)
    res.status(500).json({ error: 'Error al eliminar' })
  }
})

app.put('/horas/:id/validar', verifyToken, async (req, res) => {
  if (req.user.role === 'operario') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const horaId = parseInt(req.params.id)
  const { estado } = req.body
  const nuevoEstado = estado === 'validado' ? 'validado' : 'rechazado'
  
  try {
    const result = await dbQuery(
      'UPDATE horas_trabajo SET estado = $1 WHERE id = $2 RETURNING *',
      [nuevoEstado, horaId]
    )
    
    if (result.success && result.rows.length > 0) {
      res.json(result.rows[0])
    } else {
      res.status(404).json({ error: 'Registro no encontrado' })
    }
  } catch (error) {
    console.error('Error validating hora:', error)
    res.status(500).json({ error: 'Error al validar' })
  }
})

// ===== AVISOS ENDPOINTS (CON PERSISTENCIA) =====
app.get('/avisos', verifyToken, async (req, res) => {
  try {
    const result = await dbQuery('SELECT * FROM avisos_trabajo ORDER BY id DESC')
    res.json(result.success ? result.rows : [])
  } catch (error) {
    res.json([])
  }
})

app.get('/avisos/activos', verifyToken, async (req, res) => {
  try {
    const result = await dbQuery("SELECT * FROM avisos_trabajo WHERE estado = 'en_curso' ORDER BY id DESC")
    res.json(result.success ? result.rows : [])
  } catch (error) {
    res.json([])
  }
})

app.post('/avisos', verifyToken, verifyAdmin, async (req, res) => {
  const { numero, cliente, descripcion, estado, fecha, alertas_email } = req.body
  if (!numero || !cliente || !descripcion || !fecha) {
    return res.status(400).json({ error: 'Campos requeridos: numero, cliente, descripcion, fecha' })
  }
  
  try {
    const result = await dbQuery(
      'INSERT INTO avisos_trabajo (numero, cliente, descripcion, estado, fecha, alertas_email) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [numero, cliente, descripcion, estado || 'en_curso', fecha, JSON.stringify(alertas_email || [])]
    )
    
    if (result.success && result.rows.length > 0) {
      res.status(201).json(result.rows[0])
    } else {
      res.status(500).json({ error: 'Error al crear aviso' })
    }
  } catch (error) {
    console.error('Error creating aviso:', error)
    res.status(500).json({ error: 'Error al crear aviso' })
  }
})

app.put('/avisos/:id', verifyToken, verifyAdmin, async (req, res) => {
  const avisoId = parseInt(req.params.id)
  const { numero, cliente, descripcion, estado, fecha, alertas_email } = req.body
  
  try {
    const result = await dbQuery(
      'UPDATE avisos_trabajo SET numero=$1, cliente=$2, descripcion=$3, estado=$4, fecha=$5, alertas_email=$6 WHERE id=$7 RETURNING *',
      [numero, cliente, descripcion, estado, fecha, JSON.stringify(alertas_email || []), avisoId]
    )
    
    if (result.success && result.rows.length > 0) {
      res.json(result.rows[0])
    } else {
      res.status(404).json({ error: 'Aviso no encontrado' })
    }
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar aviso' })
  }
})

app.delete('/avisos/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await dbQuery('DELETE FROM avisos_trabajo WHERE id = $1', [parseInt(req.params.id)])
    res.json({ message: 'Eliminado' })
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar' })
  }
})

// ===== OBRAS ENDPOINTS (CON PERSISTENCIA) =====
app.get('/obras', verifyToken, async (req, res) => {
  try {
    const result = await dbQuery('SELECT * FROM obras_trabajo ORDER BY id DESC')
    res.json(result.success ? result.rows : [])
  } catch (error) {
    res.json([])
  }
})

app.get('/obras/activas', verifyToken, async (req, res) => {
  try {
    const result = await dbQuery("SELECT * FROM obras_trabajo WHERE estado = 'en_curso' ORDER BY id DESC")
    res.json(result.success ? result.rows : [])
  } catch (error) {
    res.json([])
  }
})

app.post('/obras', verifyToken, verifyAdmin, async (req, res) => {
  const { numero, cliente, descripcion, estado, fecha, fecha_fin_estimada, alertas_email } = req.body
  if (!numero || !cliente || !descripcion || !fecha) {
    return res.status(400).json({ error: 'Campos requeridos: numero, cliente, descripcion, fecha' })
  }
  
  try {
    const result = await dbQuery(
      'INSERT INTO obras_trabajo (numero, cliente, descripcion, estado, fecha, fecha_fin_estimada, alertas_email) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [numero, cliente, descripcion, estado || 'en_curso', fecha, fecha_fin_estimada || null, JSON.stringify(alertas_email || [])]
    )
    
    if (result.success && result.rows.length > 0) {
      res.status(201).json(result.rows[0])
    } else {
      res.status(500).json({ error: 'Error al crear obra' })
    }
  } catch (error) {
    console.error('Error creating obra:', error)
    res.status(500).json({ error: 'Error al crear obra' })
  }
})

app.put('/obras/:id', verifyToken, verifyAdmin, async (req, res) => {
  const obraId = parseInt(req.params.id)
  const { numero, cliente, descripcion, estado, fecha, fecha_fin_estimada, alertas_email } = req.body
  
  try {
    const result = await dbQuery(
      'UPDATE obras_trabajo SET numero=$1, cliente=$2, descripcion=$3, estado=$4, fecha=$5, fecha_fin_estimada=$6, alertas_email=$7 WHERE id=$8 RETURNING *',
      [numero, cliente, descripcion, estado, fecha, fecha_fin_estimada, JSON.stringify(alertas_email || []), obraId]
    )
    
    if (result.success && result.rows.length > 0) {
      res.json(result.rows[0])
    } else {
      res.status(404).json({ error: 'Obra no encontrada' })
    }
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar obra' })
  }
})

app.delete('/obras/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await dbQuery('DELETE FROM obras_trabajo WHERE id = $1', [parseInt(req.params.id)])
    res.json({ message: 'Eliminado' })
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar' })
  }
})

// ===== MANTENIMIENTOS ENDPOINTS (CON PERSISTENCIA) =====
app.get('/mantenimientos', verifyToken, async (req, res) => {
  try {
    const result = await dbQuery('SELECT * FROM mantenimientos_trabajo ORDER BY id DESC')
    res.json(result.success ? result.rows : [])
  } catch (error) {
    res.json([])
  }
})

app.get('/mantenimientos/activos', verifyToken, async (req, res) => {
  try {
    const result = await dbQuery("SELECT * FROM mantenimientos_trabajo WHERE estado = 'activo' ORDER BY id DESC")
    res.json(result.success ? result.rows : [])
  } catch (error) {
    res.json([])
  }
})

app.post('/mantenimientos', verifyToken, verifyAdmin, async (req, res) => {
  const { descripcion, tipo_alerta, cliente, estado, primera_alerta, alertas_email } = req.body
  if (!descripcion || !tipo_alerta || !cliente || !primera_alerta) {
    return res.status(400).json({ error: 'Campos requeridos: descripcion, tipo_alerta, cliente, primera_alerta' })
  }
  if (!['semanal', 'mensual', 'trimestral', 'anual'].includes(tipo_alerta)) {
    return res.status(400).json({ error: 'tipo_alerta debe ser: semanal, mensual, trimestral, anual' })
  }
  
  const proxima_alerta = calcularProximaAlerta(tipo_alerta, primera_alerta)
  
  try {
    const result = await dbQuery(
      'INSERT INTO mantenimientos_trabajo (descripcion, cliente, tipo_alerta, primera_alerta, proxima_alerta, estado, alertas_email) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [descripcion, cliente, tipo_alerta, primera_alerta, proxima_alerta, estado || 'activo', JSON.stringify(alertas_email || [])]
    )
    
    if (result.success && result.rows.length > 0) {
      res.status(201).json(result.rows[0])
    } else {
      res.status(500).json({ error: 'Error al crear mantenimiento' })
    }
  } catch (error) {
    console.error('Error creating mantenimiento:', error)
    res.status(500).json({ error: 'Error al crear mantenimiento' })
  }
})

app.put('/mantenimientos/:id', verifyToken, verifyAdmin, async (req, res) => {
  const mantId = parseInt(req.params.id)
  const { descripcion, tipo_alerta, cliente, estado, primera_alerta, alertas_email } = req.body
  
  const proxima_alerta = tipo_alerta && primera_alerta ? calcularProximaAlerta(tipo_alerta, primera_alerta) : null
  
  try {
    const result = await dbQuery(
      'UPDATE mantenimientos_trabajo SET descripcion=$1, cliente=$2, tipo_alerta=$3, primera_alerta=$4, proxima_alerta=COALESCE($5, proxima_alerta), estado=$6, alertas_email=$7 WHERE id=$8 RETURNING *',
      [descripcion, cliente, tipo_alerta, primera_alerta, proxima_alerta, estado, JSON.stringify(alertas_email || []), mantId]
    )
    
    if (result.success && result.rows.length > 0) {
      res.json(result.rows[0])
    } else {
      res.status(404).json({ error: 'Mantenimiento no encontrado' })
    }
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar mantenimiento' })
  }
})

app.delete('/mantenimientos/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await dbQuery('DELETE FROM mantenimientos_trabajo WHERE id = $1', [parseInt(req.params.id)])
    res.json({ message: 'Eliminado' })
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar' })
  }
})

// ===== USUARIOS ENDPOINTS (CON PERSISTENCIA) =====
app.get('/usuarios', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  try {
    const result = await dbQuery('SELECT id, email, nombre, role, activo FROM usuarios_horas ORDER BY id')
    if (result.success && result.rows.length > 0) {
      res.json(result.rows)
    } else {
      res.json(usuarios.map(u => ({
        id: u.id,
        email: u.email,
        nombre: u.nombre,
        role: u.role,
        activo: true
      })))
    }
  } catch (error) {
    res.json(usuarios.map(u => ({
      id: u.id,
      email: u.email,
      nombre: u.nombre,
      role: u.role,
      activo: true
    })))
  }
})

app.post('/usuarios', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const { email, nombre, role, password } = req.body
  if (!email || !nombre || !role) {
    return res.status(400).json({ error: 'Campos requeridos: email, nombre, role' })
  }
  
  const hashedPassword = bcrypt.hashSync(password || 'TempPassword2025!', 10)
  
  try {
    const result = await dbQuery(
      'INSERT INTO usuarios_horas (email, nombre, role, password) VALUES ($1, $2, $3, $4) RETURNING id, email, nombre, role, activo',
      [email, nombre, role, hashedPassword]
    )
    
    if (result.success && result.rows.length > 0) {
      usuarios.push({
        id: result.rows[0].id,
        email,
        nombre,
        role,
        password: hashedPassword
      })
      res.status(201).json(result.rows[0])
    } else {
      res.status(500).json({ error: 'Error al crear usuario' })
    }
  } catch (error) {
    console.error('Error creating user:', error)
    res.status(500).json({ error: 'Error al crear usuario (email duplicado?)' })
  }
})

app.put('/usuarios/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const userId = parseInt(req.params.id)
  const { email, nombre, role, password } = req.body
  
  try {
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
      const idx = usuarios.findIndex(u => u.id === userId)
      if (idx !== -1) {
        usuarios[idx].email = email
        usuarios[idx].nombre = nombre
        usuarios[idx].role = role
        if (password) usuarios[idx].password = bcrypt.hashSync(password, 10)
      }
      res.json(result.rows[0])
    } else {
      res.status(404).json({ error: 'Usuario no encontrado' })
    }
  } catch (error) {
    console.error('Error updating user:', error)
    res.status(500).json({ error: 'Error al actualizar usuario' })
  }
})

app.delete('/usuarios/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const userId = parseInt(req.params.id)
  
  try {
    await dbQuery('UPDATE usuarios_horas SET activo = false WHERE id = $1', [userId])
    usuarios = usuarios.filter(u => u.id !== userId)
    res.json({ message: 'Usuario eliminado' })
  } catch (error) {
    console.error('Error deleting user:', error)
    res.status(500).json({ error: 'Error al eliminar usuario' })
  }
})

// ===== ROLES ENDPOINTS (CON PERSISTENCIA) =====
app.get('/roles', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  try {
    const result = await dbQuery('SELECT * FROM roles_horas ORDER BY id')
    if (result.success && result.rows.length > 0) {
      res.json(result.rows)
    } else {
      res.json(roles)
    }
  } catch (error) {
    res.json(roles)
  }
})

app.put('/roles/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const roleId = parseInt(req.params.id)
  const { permisos } = req.body
  
  if (!Array.isArray(permisos)) {
    return res.status(400).json({ error: 'permisos debe ser un array' })
  }
  
  try {
    const result = await dbQuery(
      'UPDATE roles_horas SET permisos = $1 WHERE id = $2 RETURNING *',
      [JSON.stringify(permisos), roleId]
    )
    
    if (result.success && result.rows.length > 0) {
      const idx = roles.findIndex(r => r.id === roleId)
      if (idx !== -1) {
        roles[idx].permisos = permisos
      }
      res.json(result.rows[0])
    } else {
      res.status(404).json({ error: 'Rol no encontrado' })
    }
  } catch (error) {
    console.error('Error updating role:', error)
    res.status(500).json({ error: 'Error al actualizar rol' })
  }
})

app.post('/roles', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const { nombre, permisos } = req.body
  
  if (!nombre || typeof nombre !== 'string') {
    return res.status(400).json({ error: 'El nombre del rol es obligatorio' })
  }
  
  const nombreNormalizado = nombre.toLowerCase().trim()
  
  try {
    const existing = await dbQuery('SELECT id FROM roles_horas WHERE nombre = $1', [nombreNormalizado])
    if (existing.success && existing.rows.length > 0) {
      return res.status(400).json({ error: 'Ya existe un rol con ese nombre' })
    }
    
    const result = await dbQuery(
      'INSERT INTO roles_horas (nombre, permisos) VALUES ($1, $2) RETURNING *',
      [nombreNormalizado, JSON.stringify(permisos || [])]
    )
    
    if (result.success && result.rows.length > 0) {
      const newRole = {
        id: result.rows[0].id,
        nombre: result.rows[0].nombre,
        permisos: permisos || []
      }
      roles.push(newRole)
      res.status(201).json(newRole)
    } else {
      res.status(500).json({ error: 'Error al crear rol' })
    }
  } catch (error) {
    console.error('Error creating role:', error)
    res.status(500).json({ error: 'Error al crear rol' })
  }
})

app.delete('/roles/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const roleId = parseInt(req.params.id)
  
  try {
    const roleToDelete = await dbQuery('SELECT nombre FROM roles_horas WHERE id = $1', [roleId])
    if (roleToDelete.success && roleToDelete.rows.length > 0) {
      const roleName = roleToDelete.rows[0].nombre
      if (['admin', 'supervisor', 'operario'].includes(roleName)) {
        return res.status(400).json({ error: 'No se pueden eliminar los roles del sistema' })
      }
    }
    
    await dbQuery('DELETE FROM roles_horas WHERE id = $1', [roleId])
    roles = roles.filter(r => r.id !== roleId)
    res.json({ message: 'Rol eliminado correctamente' })
  } catch (error) {
    console.error('Error deleting role:', error)
    res.status(500).json({ error: 'Error al eliminar rol' })
  }
})

// ===== CONFIGURACION ENDPOINTS (CON PERSISTENCIA) =====
app.get('/configuracion', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'supervisor') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  try {
    const result = await dbQuery("SELECT valor FROM configuracion_horas WHERE clave = 'general'")
    
    if (result.success && result.rows.length > 0) {
      res.json(result.rows[0].valor)
    } else {
      res.json(configuracion)
    }
  } catch (error) {
    console.error('Error fetching config:', error)
    res.json(configuracion)
  }
})

app.put('/configuracion/empresa', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const { nombre, logo, color_primario, color_secundario } = req.body
  if (nombre) configuracion.empresa.nombre = nombre
  if (logo !== undefined) configuracion.empresa.logo = logo
  if (color_primario) configuracion.empresa.color_primario = color_primario
  if (color_secundario) configuracion.empresa.color_secundario = color_secundario
  
  try {
    await dbQuery(
      "INSERT INTO configuracion_horas (clave, valor) VALUES ($1, $2) ON CONFLICT (clave) DO UPDATE SET valor = $2",
      ['general', JSON.stringify(configuracion)]
    )
    console.log('✅ Config empresa saved to DB')
  } catch (error) {
    console.error('Error saving empresa config:', error)
  }
  
  res.json(configuracion.empresa)
})

app.put('/configuracion/bienvenida', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const { titulo, subtitulo } = req.body
  if (titulo) configuracion.bienvenida.titulo = titulo
  if (subtitulo) configuracion.bienvenida.subtitulo = subtitulo
  
  try {
    await dbQuery(
      "INSERT INTO configuracion_horas (clave, valor) VALUES ($1, $2) ON CONFLICT (clave) DO UPDATE SET valor = $2",
      ['general', JSON.stringify(configuracion)]
    )
    console.log('✅ Config bienvenida saved to DB')
  } catch (error) {
    console.error('Error saving bienvenida config:', error)
  }
  
  res.json(configuracion.bienvenida)
})

app.put('/configuracion/idioma', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const { idioma_principal, traducciones } = req.body
  if (idioma_principal) configuracion.idioma.idioma_principal = idioma_principal
  if (traducciones) configuracion.idioma.traducciones = traducciones
  
  try {
    await dbQuery(
      "INSERT INTO configuracion_horas (clave, valor) VALUES ($1, $2) ON CONFLICT (clave) DO UPDATE SET valor = $2",
      ['general', JSON.stringify(configuracion)]
    )
    console.log('✅ Config idioma saved to DB')
  } catch (error) {
    console.error('Error saving idioma config:', error)
  }
  
  res.json(configuracion.idioma)
})

app.put('/configuracion/smtp', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const { host, puerto, usuario, contraseña } = req.body
  if (host) configuracion.smtp.host = host
  if (puerto) configuracion.smtp.puerto = puerto
  if (usuario) configuracion.smtp.usuario = usuario
  if (contraseña) configuracion.smtp.contraseña = contraseña
  
  try {
    await dbQuery(
      "INSERT INTO configuracion_horas (clave, valor) VALUES ($1, $2) ON CONFLICT (clave) DO UPDATE SET valor = $2",
      ['general', JSON.stringify(configuracion)]
    )
    console.log('✅ Config SMTP saved to DB')
  } catch (error) {
    console.error('Error saving SMTP config:', error)
  }
  
  res.json(configuracion.smtp)
})

// ===== SMTP TEST ENDPOINT =====
app.post('/smtp/test', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No autorizado' })
  }
  
  const { host, puerto, usuario, contraseña, email_destino } = req.body
  
  if (!host || !usuario || !contraseña || !email_destino) {
    return res.status(400).json({ error: 'Faltan datos: host, usuario, contraseña, email_destino' })
  }
  
  try {
    const nodemailer = require('nodemailer')
    
    const transporter = nodemailer.createTransport({
      host: host,
      port: parseInt(puerto) || 587,
      secure: parseInt(puerto) === 465,
      auth: {
        user: usuario,
        pass: contraseña
      },
      tls: {
        rejectUnauthorized: false
      }
    })
    
    await transporter.verify()
    
    const info = await transporter.sendMail({
      from: `"GrupLomi Sistema" <${usuario}>`,
      to: email_destino,
      subject: '✅ Prueba SMTP - GrupLomi Horas',
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #0071e3 0%, #0051a2 100%); padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 20px;">
            <h1 style="color: white; margin: 0; font-size: 24px;">✅ Configuración SMTP Correcta</h1>
          </div>
          <div style="background: #f5f5f7; padding: 25px; border-radius: 12px;">
            <p style="color: #1d1d1f; font-size: 16px; margin: 0 0 15px 0;">Este es un email de prueba del sistema <strong>GrupLomi Horas</strong>.</p>
            <p style="color: #86868b; font-size: 14px; margin: 0 0 15px 0;">Si has recibido este mensaje, la configuración SMTP está funcionando correctamente.</p>
            <hr style="border: none; border-top: 1px solid #d2d2d7; margin: 20px 0;">
            <p style="color: #86868b; font-size: 12px; margin: 0;"><strong>Detalles de la prueba:</strong></p>
            <ul style="color: #86868b; font-size: 12px; margin: 10px 0 0 0; padding-left: 20px;">
              <li>Servidor SMTP: ${host}</li>
              <li>Puerto: ${puerto || 587}</li>
              <li>Fecha: ${new Date().toLocaleString('es-ES')}</li>
            </ul>
          </div>
          <p style="color: #86868b; font-size: 11px; text-align: center; margin-top: 20px;">Este mensaje fue enviado automáticamente por GrupLomi Horas</p>
        </div>
      `
    })
    
    console.log('✅ Test email sent:', info.messageId)
    res.json({ success: true, message: 'Email enviado correctamente', messageId: info.messageId })
    
  } catch (error) {
    console.error('❌ SMTP test error:', error)
    
    let errorMsg = error.message
    if (error.code === 'EAUTH') {
      errorMsg = 'Error de autenticación: Usuario o contraseña incorrectos. Si usas Gmail, necesitas una "Contraseña de aplicación".'
    } else if (error.code === 'ESOCKET' || error.code === 'ECONNECTION') {
      errorMsg = 'No se pudo conectar al servidor SMTP. Verifica el host y el puerto.'
    } else if (error.code === 'ETIMEDOUT') {
      errorMsg = 'Tiempo de conexión agotado. El servidor SMTP no responde.'
    } else if (error.code === 'ECONNREFUSED') {
      errorMsg = 'Conexión rechazada. El puerto podría estar bloqueado o el servidor no está disponible.'
    }
    
    res.status(500).json({ error: errorMsg })
  }
})

// ===== HEALTH ENDPOINT =====
app.get('/health', (req, res) => {
  res.json({ status: 'ok', db: 'connected via proxy', version: '3.2' })
})

// ===== TEST DB ENDPOINT =====
app.get('/test-db', async (req, res) => {
  try {
    const result = await dbQuery('SELECT 1 as test')
    res.json({ status: 'ok', db: 'connected', result: result.rows })
  } catch (error) {
    res.json({ status: 'error', message: error.message })
  }
})

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' })
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
  console.log('🚀 Backend v3.2 running on port ' + PORT)
  console.log('✅ Full PostgreSQL persistence enabled')
})

module.exports = app
