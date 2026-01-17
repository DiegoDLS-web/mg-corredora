const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path'); 

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = "mi_secreto_super_seguro"; // En producción usa env

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- RUTAS PÚBLICAS ---

// Obtener propiedades (Con filtro opcional por Corredor)
app.get('/api/propiedades', async (req, res) => {
    try {
        const { corredor } = req.query; 
        
        let filtro = {};
        
        // Si viene el parámetro corredor, filtramos
        if (corredor && corredor !== 'null' && corredor !== 'undefined') {
            filtro = { 
                corredora: {
                    equals: corredor,
                    // mode: 'insensitive' // Descomentar si usas Postgres
                }
            };
        }

        const propiedades = await prisma.propiedad.findMany({ 
            where: filtro,
            orderBy: { createdAt: 'desc' } 
        });
        
        res.json(propiedades);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al obtener propiedades" });
    }
});

// Login (Admin y Corredor)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const usuario = await prisma.usuario.findUnique({ where: { email } });
        
        if (!usuario) return res.status(401).json({ error: "Credenciales incorrectas" });

        const valid = await bcrypt.compare(password, usuario.password);
        if (!valid) return res.status(401).json({ error: "Credenciales incorrectas" });

        // Si no tiene rol en DB, asumimos admin (seguridad por defecto)
        const userRole = usuario.rol || 'admin'; 
        const userName = usuario.nombre || 'Administrador';

        const token = jwt.sign({ 
            id: usuario.id, 
            email: usuario.email,
            rol: userRole,
            nombre: userName
        }, SECRET_KEY, { expiresIn: '8h' });

        res.json({ 
            token, 
            email: usuario.email,
            nombre: userName,
            rol: userRole
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// --- RUTAS DE VISTAS (HTML) ---
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/panel-corredor', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'panel-corredor.html'));
});

// --- MIDDLEWARE DE SEGURIDAD ---
const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    
    if (!token) return res.status(401).json({ error: "Acceso denegado" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Token inválido" });
        req.user = user;
        next();
    });
};

// --- RUTAS PROTEGIDAS (PROPIEDADES) ---

// Crear propiedad 
app.post('/api/propiedades', verificarToken, async (req, res) => {
    try {
        const datos = req.body;
        // Si es corredor, forzamos su nombre
        if (req.user.rol === 'corredor') {
            datos.corredora = req.user.nombre; 
        }
        const nueva = await prisma.propiedad.create({ data: datos });
        res.json(nueva);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Error al crear" });
    }
});

// Editar propiedad
app.put('/api/propiedades/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const datos = req.body;
        
        // Seguridad: Si es corredor, solo edita lo suyo
        if (req.user.rol === 'corredor') {
            const propExistente = await prisma.propiedad.findUnique({ where: { id: parseInt(id) } });
            if (!propExistente || propExistente.corredora !== req.user.nombre) {
                return res.status(403).json({ error: "No tienes permiso para editar esta propiedad" });
            }
        }

        delete datos.id;
        delete datos.createdAt;

        const actualizada = await prisma.propiedad.update({
            where: { id: parseInt(id) },
            data: datos
        });
        res.json(actualizada);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Error al actualizar" });
    }
});

// Eliminar propiedad
app.delete('/api/propiedades/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Seguridad: Si es corredor, solo borra lo suyo
        if (req.user.rol === 'corredor') {
            const propExistente = await prisma.propiedad.findUnique({ where: { id: parseInt(id) } });
            if (!propExistente || propExistente.corredora !== req.user.nombre) {
                return res.status(403).json({ error: "No tienes permiso para eliminar esta propiedad" });
            }
        }

        await prisma.propiedad.delete({ where: { id: parseInt(id) } });
        res.json({ message: "Eliminada correctamente" });
    } catch (e) {
        res.status(500).json({ error: "Error al eliminar" });
    }
});

// --- GESTIÓN DE USUARIOS (Solo Admin) ---

// Crear Corredor
app.post('/api/usuarios', verificarToken, async (req, res) => {
    try {
        if (req.user.rol !== 'admin') {
            return res.status(403).json({ error: "No tienes permisos de administrador" });
        }

        const { email, password, nombre } = req.body;

        const existe = await prisma.usuario.findUnique({ where: { email } });
        if (existe) return res.status(400).json({ error: "El correo ya está registrado" });

        const hashedPassword = await bcrypt.hash(password, 10);

        const nuevoUsuario = await prisma.usuario.create({
            data: {
                email,
                password: hashedPassword,
                nombre,
                rol: 'corredor' 
            }
        });

        res.json({ message: "Corredor creado con éxito", id: nuevoUsuario.id });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Error al crear usuario" });
    }
});

// Listar Corredores
app.get('/api/usuarios', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: "Sin permiso" });
    
    const usuarios = await prisma.usuario.findMany({
        where: { rol: 'corredor' },
        select: { id: true, nombre: true, email: true }
    });
    res.json(usuarios);
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor listo en http://localhost:${PORT}`);
});