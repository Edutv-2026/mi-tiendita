const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');

// --- CARGA DE VARIABLES DE ENTORNO (Para Hosting) ---
const PORT = process.env.PORT || 5000;
const ACCESS_SECRET = process.env.JWT_SECRET || "NITRO_ACCESS_2026";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "NITRO_REFRESH_2026";
const ADMIN_REGISTRATION_CODE = "Edutv"; 

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// --- MIDDLEWARES DE SEGURIDAD (REQUERIMIENTO PROFE) ---
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors());
app.use(express.json());
app.use(morgan('combined')); // Auditoría: Monitoreo de cada acceso
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Protección contra ataques de fuerza bruta
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

// --- CONEXIÓN A BASE DE DATOS (Configurada para local y remoto) ---
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'root',
  database: process.env.DB_NAME || 'mi-tiendita',
  port: process.env.DB_PORT || 3306,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : null
});

db.connect(err => {
  if (err) console.log("❌ Error DB:", err.message);
  else console.log("✅ Conectado a la base de datos");
});

// --- SISTEMA DE LOGS (MONITOREO) ---
const registrarLog = (usuario, accion, ip) => {
    db.query('INSERT INTO logs (usuario, accion, ip_address) VALUES (?, ?, ?)', [usuario || 'Sistema', accion, ip || '0.0.0.0']);
};

// --- MIDDLEWARE AVANZADO: JWT + RBAC (Roles) ---
const verificarPermisos = (rolesPermitidos = []) => {
  return (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).json({ error: "Token requerido" });

    jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
      if (err) return res.status(401).json({ error: "Token expirado o inválido" });
      
      req.user = decoded; 
      // RBAC: Verificamos si el rol tiene permiso para esta ruta
      if (rolesPermitidos.length && !rolesPermitidos.includes(req.user.rol)) {
        registrarLog(req.user.user, "INTENTO DE ACCESO NO AUTORIZADO A RUTA", req.ip);
        return res.status(403).json({ error: "No tienes permisos suficientes para esta acción" });
      }
      next();
    });
  };
};

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// --- LÓGICA MULTISESIÓN (SOCKETS) ---
let sesionesActivas = {}; 
io.on('connection', (socket) => {
  socket.on('register_connection', (username) => {
    socket.username = username;
    if (!sesionesActivas[username]) sesionesActivas[username] = [];
    sesionesActivas[username].push(socket.id);
    io.emit('online_users_list', Object.keys(sesionesActivas).map(u => ({ nombre: u, sesiones: sesionesActivas[u].length })));
  });
  socket.on('disconnect', () => {
    const u = socket.username;
    if (sesionesActivas[u]) {
      sesionesActivas[u] = sesionesActivas[u].filter(id => id !== socket.id);
      if (sesionesActivas[u].length === 0) delete sesionesActivas[u];
    }
    io.emit('online_users_list', Object.keys(sesionesActivas).map(u => ({ nombre: u, sesiones: sesionesActivas[u] ? sesionesActivas[u].length : 0 })));
  });
});

// --- RUTAS DE AUTENTICACIÓN ---

app.post('/api/register', async (req, res) => {
  const { usuario, email, telefono, clave, rol, codigoAdmin } = req.body;
  // Mapeo para MySQL
  const rolesMap = { "Administrador": "admin", "Vendedor": "user", "Editor": "editor" };
  const rolReal = rolesMap[rol] || 'user';

  if (rolReal === 'admin' && codigoAdmin !== ADMIN_REGISTRATION_CODE) {
    return res.status(403).json({ error: "Código de Autorización Incorrecto" });
  }

  try {
    const hash = await bcrypt.hash(clave, 10);
    const sql = 'INSERT INTO usuarios (usuario, email, telefono, clave, rol) VALUES (?, ?, ?, ?, ?)';
    db.query(sql, [usuario, email, telefono || '', hash, rolReal], (err) => {
      if (err) return res.status(500).json({ error: "Usuario o Email ya existe" });
      registrarLog(usuario, "REGISTRO EXITOSO", req.ip);
      res.json({ success: true });
    });
  } catch (e) { res.status(500).json({ error: "Error interno" }); }
});

app.post('/api/login', (req, res) => {
  const { usuario, clave } = req.body;
  db.query('SELECT * FROM usuarios WHERE usuario = ?', [usuario], async (err, result) => {
    if (result && result.length > 0) {
      const match = await bcrypt.compare(clave, result[0].clave);
      if (match) {
        // Access Token (Expiración corta para seguridad)
        const accessToken = jwt.sign({ id: result[0].id, rol: result[0].rol, user: result[0].usuario }, ACCESS_SECRET, { expiresIn: '15m' });
        // Refresh Token (Larga duración)
        const refreshToken = jwt.sign({ id: result[0].id }, REFRESH_SECRET, { expiresIn: '7d' });
        
        registrarLog(usuario, "LOGIN EXITOSO", req.ip);
        res.json({ success: true, accessToken, refreshToken, user: result[0].usuario, rol: result[0].rol });
      } else res.status(401).json({ error: "Clave incorrecta" });
    } else res.status(404).json({ error: "Usuario no existe" });
  });
});

// REFRESH TOKEN (Requisito Parte 3)
app.post('/api/refresh', (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(401).json({ error: "No hay token" });
    jwt.verify(token, REFRESH_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Refresh token expirado" });
        const newAccessToken = jwt.sign({ id: decoded.id, rol: decoded.rol, user: decoded.user }, ACCESS_SECRET, { expiresIn: '15m' });
        res.json({ accessToken: newAccessToken });
    });
});

// --- RUTAS DE NEGOCIO (RBAC + ABAC) ---

app.get('/api/productos', verificarPermisos(['superadmin', 'admin', 'editor', 'user']), (req, res) => {
  db.query('SELECT * FROM productos', (err, r) => res.json(r));
});

app.get('/api/productos/buscar', verificarPermisos(['superadmin', 'admin', 'editor', 'user']), (req, res) => {
    const q = `%${req.query.q}%`;
    db.query('SELECT * FROM productos WHERE nombre LIKE ?', [q], (err, r) => res.json(r));
});

app.get('/api/stats', verificarPermisos(['superadmin', 'admin', 'editor', 'user']), (req, res) => {
    db.query('SELECT COUNT(*) as total, IFNULL(SUM(stock*precio_venta),0) as valor, (SELECT COUNT(*) FROM productos WHERE stock < 10) as bajo FROM productos', (err, r) => {
      res.json({ total_productos: r[0].total, valor_inventario: r[0].valor, bajo_stock: r[0].bajo });
    });
});

// ABAC: Registramos quién creó el producto (created_by)
app.post('/api/productos', verificarPermisos(['superadmin', 'admin', 'editor']), upload.single('imagen'), (req, res) => {
  const { nombre, stock, precio_venta } = req.body;
  const imagen = req.file ? req.file.filename : null;
  const sql = 'INSERT INTO productos (nombre, imagen, stock, precio_venta, created_by) VALUES (?, ?, ?, ?, ?)';
  db.query(sql, [nombre, imagen, stock, precio_venta, req.user.id], () => {
      registrarLog(req.user.user, `AGREGÓ PRODUCTO: ${nombre}`, req.ip);
      res.json({ success: true });
  });
});

// RBAC: Solo admin o superadmin borran
app.delete('/api/productos/:id', verificarPermisos(['superadmin', 'admin']), (req, res) => {
  db.query('DELETE FROM productos WHERE id = ?', [req.params.id], () => {
      registrarLog(req.user.user, `ELIMINÓ PRODUCTO ID: ${req.params.id}`, req.ip);
      res.json({ success: true });
  });
});

// SUPER USUARIO: EXPULSIÓN
app.post('/api/kick', verificarPermisos(['superadmin']), (req, res) => {
  if (req.user.user !== 'Eduardo Mtz') return res.status(403).send("Solo el dueño");
  const { usuarioExpulsar } = req.body;
  if (sesionesActivas[usuarioExpulsar]) {
    sesionesActivas[usuarioExpulsar].forEach(sid => io.to(sid).emit('force_logout'));
    delete sesionesActivas[usuarioExpulsar];
    registrarLog(req.user.user, `EXPULSÓ A: ${usuarioExpulsar}`, req.ip);
    res.json({ success: true });
  } else res.status(404).send("Offline");
});

app.get('/api/logs', verificarPermisos(['superadmin']), (req, res) => {
    db.query('SELECT * FROM logs ORDER BY fecha DESC LIMIT 50', (err, r) => res.json(r));
});

server.listen(PORT, () => console.log(`SERVIDOR ${PORT}`));