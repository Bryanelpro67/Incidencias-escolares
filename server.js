const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || "mi_clave_secreta_jwt";

// --- MIDDLEWARES ---
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// --- CONEXIÓN A LA BASE DE DATOS ---
const conexion = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "incidencias_escolares",
  port: process.env.DB_PORT || 3306,
  ssl: process.env.DB_HOST ? { rejectUnauthorized: false } : false
});

conexion.connect((err) => {
  if (err) {
    console.error("Error de conexión a la BD:", err.message);
  } else {
    console.log("Conexión exitosa a la Base de Datos");
  }
});

// --- CONFIGURACIÓN DE MULTER (CARGA DE ARCHIVOS) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

// --- MIDDLEWARE DE AUTENTICACIÓN ---
const verificarToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ mensaje: "Token no proporcionado" });
  }

  jwt.verify(token.replace("Bearer ", ""), SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ mensaje: "Token inválido o expirado" });
    }
    req.usuario = decoded;
    next();
  });
};

// ==========================================
// --- RUTAS DE AUTENTICACIÓN Y USUARIOS ---
// ==========================================

app.post("/registro", async (req, res) => {
  const { nombre, email, password, rol } = req.body;

  try {
    const hash = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)";
    
    conexion.query(sql, [nombre, email, hash, rol || "Usuario"], (error) => {
      if (error) return res.status(500).json(error);
      res.json({ mensaje: "Usuario registrado con éxito" });
    });
  } catch (error) {
    res.status(500).json({ mensaje: "Error al procesar la contraseña" });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM usuarios WHERE email = ?";

  conexion.query(sql, [email], async (error, resultado) => {
    if (error) return res.status(500).json(error);
    if (resultado.length === 0) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }

    const usuario = resultado[0];
    const passwordValida = await bcrypt.compare(password, usuario.password);
    if (!passwordValida) {
      return res.status(401).json({ mensaje: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { id: usuario.id, rol: usuario.rol }, 
      SECRET_KEY, 
      { expiresIn: "8h" }
    );

    res.json({
      mensaje: "Inicio de sesión exitoso",
      token,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol
      }
    });
  });
});

app.get("/perfil", verificarToken, (req, res) => {
  const usuarioId = req.usuario.id;
  const sql = "SELECT id, nombre, email, rol FROM usuarios WHERE id = ?";

  conexion.query(sql, [usuarioId], (error, resultado) => {
    if (error) return res.status(500).json(error);
    if (resultado.length === 0) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }
    res.json(resultado[0]);
  });
});

// ==========================================
// --- RUTAS DE CATEGORÍAS ---
// ==========================================

app.get("/categorias", (req, res) => {
  conexion.query("SELECT * FROM categorias", (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json(resultado);
  });
});

// ==========================================
// --- RUTAS DE INCIDENCIAS ---
// ==========================================

app.get("/incidencias", (req, res) => {
  const { buscar, categoria_id, estado } = req.query;
  let sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha, i.imagen, c.nombre AS categoria
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    WHERE 1=1
  `;
  const parametros = [];

  if (buscar) {
    sql += " AND i.descripcion LIKE ?";
    parametros.push(`%${buscar}%`);
  }
  if (categoria_id) {
    sql += " AND i.categoria_id = ?";
    parametros.push(categoria_id);
  }
  if (estado) {
    sql += " AND i.estado = ?";
    parametros.push(estado);
  }

  sql += " ORDER BY i.fecha DESC";

  conexion.query(sql, parametros, (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json(resultado);
  });
});

app.get("/incidencias/exportar", (req, res) => {
  const { fecha_inicio, fecha_fin } = req.query;
  let sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha, c.nombre AS categoria
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    WHERE 1=1
  `;
  const parametros = [];

  if (fecha_inicio && fecha_fin) {
    sql += " AND DATE(i.fecha) BETWEEN ? AND ?";
    parametros.push(fecha_inicio, fecha_fin);
  }

  sql += " ORDER BY i.fecha DESC";

  conexion.query(sql, parametros, (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json(resultado);
  });
});

app.post("/incidencias", upload.single("imagen"), (req, res) => {
  const { categoria_id, descripcion, usuario_id } = req.body;
  const imagen = req.file ? req.file.filename : null;

  const sql = "INSERT INTO incidencias (usuario_id, categoria_id, descripcion, imagen) VALUES (?, ?, ?, ?)";

  conexion.query(sql, [usuario_id || null, categoria_id, descripcion, imagen], (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json({
      mensaje: "Incidencia registrada correctamente",
      id: resultado.insertId
    });
  });
});

app.put("/incidencias/:id/estado", verificarToken, (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;
  const sql = "UPDATE incidencias SET estado = ? WHERE id = ?";

  conexion.query(sql, [estado, id], (error) => {
    if (error) return res.status(500).json(error);
    res.json({ mensaje: "Estado actualizado correctamente" });
  });
});

app.delete("/incidencias/:id", verificarToken, (req, res) => {
  const { id } = req.params;

  if (req.usuario.rol !== "Admin") {
    return res.status(403).json({ mensaje: "Acceso denegado: Requiere rol Admin" });
  }

  const sql = "DELETE FROM incidencias WHERE id = ?";
  conexion.query(sql, [id], (error) => {
    if (error) return res.status(500).json(error);
    res.json({ mensaje: "Incidencia eliminada correctamente" });
  });
});

// --- INICIO DEL SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor activo en el puerto ${PORT}`);
});