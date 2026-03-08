const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path'); 

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = "mi_secreto_super_seguro"; 

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- CONTADOR DE VISITAS ---
let contadorVisitas = 0;

// Este middleware cuenta cada vez que alguien entra a tu página de inicio pública
app.use((req, res, next) => {
    if (req.path === '/' || req.path === '/index.html') {
        contadorVisitas++;
    }
    next();
});

// Ruta que le envía el total al panel de administrador
app.get('/api/visitas', (req, res) => {
    res.json({ visitas: contadorVisitas });
});

// --- RUTAS DE VISTAS ---
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/panel-corredor', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'panel-corredor.html'));
});

// --- API: LOGIN (CON AUTO-REPARACIÓN PARA TI) ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const usuario = await prisma.usuario.findUnique({ where: { email } });
        
        if (!usuario) return res.status(401).json({ error: "Credenciales incorrectas" });

        const valid = await bcrypt.compare(password, usuario.password);
        if (!valid) return res.status(401).json({ error: "Credenciales incorrectas" });

        // --- BLOQUE DE AUTO-REPARACIÓN PARA EL ADMIN ---
        // Si es TU correo, forzamos que seas Admin sí o sí.
        if (email === 'admin@mgpropiedades.cl') {
            if (usuario.rol !== 'admin') {
                await prisma.usuario.update({
                    where: { email },
                    data: { rol: 'admin', nombre: 'Administrador MG' }
                });
                usuario.rol = 'admin'; // Actualizamos en memoria
            }
        }
        // ------------------------------------------------

        const userRole = usuario.rol || 'corredor'; 
        const userName = usuario.nombre || 'Usuario';

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

// --- API: PROPIEDADES (PÚBLICA) ---
app.get('/api/propiedades', async (req, res) => {
    try {
        const { corredor } = req.query; 
        let filtro = {};
        
        // Si piden filtrar por corredor (para el panel de corredor)
        if (corredor && corredor !== 'null' && corredor !== 'undefined') {
            filtro = { corredora: { equals: corredor } };
        }

        const propiedades = await prisma.propiedad.findMany({ 
            where: filtro,
            orderBy: { createdAt: 'desc' } 
        });
        
        res.json(propiedades);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener propiedades" });
    }
});

// --- MIDDLEWARE SEGURIDAD ---
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

// --- API: CREAR/EDITAR/BORRAR PROPIEDADES ---

app.post('/api/propiedades', verificarToken, async (req, res) => {
    try {
        const datos = req.body;
        // Si es corredor, forzamos su nombre como autor
        if (req.user.rol === 'corredor') {
            datos.corredora = req.user.nombre; 
        }
        // Si es admin, usa el nombre que venga (o por defecto MG)
        const nueva = await prisma.propiedad.create({ data: datos });
        res.json(nueva);
    } catch (e) {
        res.status(500).json({ error: "Error al crear" });
    }
});

app.put('/api/propiedades/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const datos = req.body;
        
        // Seguridad para Corredor: Solo edita lo suyo
        if (req.user.rol === 'corredor') {
            const prop = await prisma.propiedad.findUnique({ where: { id: parseInt(id) } });
            if (!prop || prop.corredora !== req.user.nombre) {
                return res.status(403).json({ error: "No es tu propiedad" });
            }
        }
        
        delete datos.id;
        delete datos.createdAt;
        const actualizada = await prisma.propiedad.update({ where: { id: parseInt(id) }, data: datos });
        res.json(actualizada);
    } catch (e) {
        res.status(500).json({ error: "Error al actualizar" });
    }
});

app.delete('/api/propiedades/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        // Seguridad para Corredor: Solo borra lo suyo
        if (req.user.rol === 'corredor') {
            const prop = await prisma.propiedad.findUnique({ where: { id: parseInt(id) } });
            if (!prop || prop.corredora !== req.user.nombre) {
                return res.status(403).json({ error: "No es tu propiedad" });
            }
        }
        await prisma.propiedad.delete({ where: { id: parseInt(id) } });
        res.json({ message: "Eliminada" });
    } catch (e) {
        res.status(500).json({ error: "Error al eliminar" });
    }
});

// --- API: CREAR USUARIOS (SOLO ADMIN) ---
app.post('/api/usuarios', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: "Solo Admin" });

    const { email, password, nombre } = req.body;
    try {
        const existe = await prisma.usuario.findUnique({ where: { email } });
        if (existe) return res.status(400).json({ error: "Correo ocupado" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const nuevo = await prisma.usuario.create({
            data: { email, password: hashedPassword, nombre, rol: 'corredor' }
        });
        res.json({ message: "Creado", id: nuevo.id });
    } catch (e) {
        res.status(500).json({ error: "Error al crear usuario" });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor listo en http://localhost:${PORT}`);
});