const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = "mi_secreto_super_seguro"; // En producción usa una variable de entorno

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- RUTAS PÚBLICAS ---

// Obtener propiedades
app.get('/api/propiedades', async (req, res) => {
    const propiedades = await prisma.propiedad.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(propiedades);
});

// Login de Administrador
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    // Buscar usuario
    const usuario = await prisma.usuario.findUnique({ where: { email } });
    if (!usuario) return res.status(401).json({ error: "Credenciales incorrectas" });

    // Verificar contraseña
    const valid = await bcrypt.compare(password, usuario.password);
    if (!valid) return res.status(401).json({ error: "Credenciales incorrectas" });

    // Crear Token
    const token = jwt.sign({ id: usuario.id, email: usuario.email }, SECRET_KEY, { expiresIn: '8h' });
    res.json({ token, email: usuario.email });
});

// --- RUTAS PROTEGIDAS (Requieren Token) ---

// Middleware para verificar que sea admin
const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"
    
    if (!token) return res.status(401).json({ error: "Acceso denegado" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Token inválido" });
        req.user = user;
        next();
    });
};

// Crear propiedad (Solo Admin)
app.post('/api/propiedades', verificarToken, async (req, res) => {
    try {
        const nueva = await prisma.propiedad.create({ data: req.body });
        res.json(nueva);
    } catch (e) {
        res.status(500).json({ error: "Error al crear" });
    }
});

// Eliminar propiedad (Solo Admin)
app.delete('/api/propiedades/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        await prisma.propiedad.delete({ where: { id: parseInt(id) } });
        res.json({ message: "Eliminada correctamente" });
    } catch (e) {
        res.status(500).json({ error: "Error al eliminar" });
    }
});

// Ruta para servir el panel de admin
app.get('/admin', (req, res) => {
    res.sendFile(__dirname + '/public/admin.html');
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor listo en http://localhost:${PORT}`);
});