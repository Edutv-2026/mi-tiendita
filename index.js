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

const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "NITRO_TIENDITA_2026_JWT_SECRET";
const ADMIN_REGISTRATION_CODE = "Edutv"; 

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(helmet({ crossOriginResourcePolicy: false }));

// --- CONFIGURACIÓN DE CORS REAL ---
app.use(cors({
  origin: ["https://mi-tiendita-client-qilpkdndv-edutv.vercel.app", "https://mi-tiendita-client.vercel.app"],
  credentials: true
}));

app.use(express.json());
app.use(morgan('combined')); 
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false }
});

db.connect(err => {
  if (err) console.log("❌ Error DB:", err.message);
  else console.log("✅ Conectado a la base de datos");
});

const verificarToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(403).json({ error: "No autorizado" });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Sesión expirada" });
    req.user = decoded;
    next();
  });
};

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

let conectados = {};
io.on('connection', (socket) => {
  socket.on('register', (userId) => {
    conectados[userId] = socket.id;
  });
});

// --- REGISTRO CORREGIDO ---
app.post('/api/register', async (req, res) => {
  const { usuario, email, telefono, clave, rol, codigoAdmin } = req.body;
  
  // Convertimos 'Vendedor' a 'user' y 'Administrador' a 'admin' para que MySQL no lo rechace
  const rolesMap = { "Administrador": "admin", "Vendedor": "user" };
  const rolReal = rolesMap[rol] || 'user';

  if (rolReal === 'admin' && codigoAdmin !== ADMIN_REGISTRATION_CODE) {
    return res.status(403).json({ error: "Código Admin inválido" });
  }

  try {
    const hash = await bcrypt.hash(clave, 10);
    const sql = 'INSERT INTO usuarios (usuario, email, telefono, clave, rol) VALUES (?, ?, ?, ?, ?)';
    db.query(sql, [usuario, email, telefono, hash, rolReal], (err) => {
      if (err) {
          console.error("❌ ERROR REAL DE MYSQL:", err.sqlMessage); // ESTO SALDRÁ EN RENDER
          return res.status(500).json({ error: err.sqlMessage });
      }
      res.json({ success: true });
    });
  } catch (e) { res.status(500).json({ error: "Error de servidor" }); }
});

app.post('/api/login', (req, res) => {
  const { usuario, clave } = req.body;
  db.query('SELECT * FROM usuarios WHERE usuario = ?', [usuario], async (err, result) => {
    if (result && result.length > 0) {
      const match = await bcrypt.compare(clave, result[0].clave);
      if (match) {
        const token = jwt.sign({ id: result[0].id, rol: result[0].rol, user: result[0].usuario }, SECRET_KEY, { expiresIn: '4h' });
        res.json({ success: true, token, user: result[0].usuario, rol: result[0].rol });
      } else res.status(401).json({ error: "Clave incorrecta" });
    } else res.status(404).json({ error: "Usuario no existe" });
  });
});

app.get('/api/productos', verificarToken, (req, res) => db.query('SELECT * FROM productos', (err, r) => res.json(r)));
app.get('/api/stats', verificarToken, (req, res) => db.query('SELECT COUNT(*) as total, IFNULL(SUM(stock*precio_venta),0) as valor, (SELECT COUNT(*) FROM productos WHERE stock < 10) as bajo FROM productos', (err, r) => res.json({total_productos: r[0].total, valor_inventario: r[0].valor, bajo_stock: r[0].bajo})));

server.listen(PORT, () => console.log('🚀 Servidor Real en puerto ' + PORT));