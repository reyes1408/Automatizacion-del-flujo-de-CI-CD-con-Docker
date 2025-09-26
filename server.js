// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const { body, validationResult } = require('express-validator');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Configuración de la base de datos
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER ,
    password: process.env.DB_PASSWORD,
    database: 'sistema_turismo',
    charset: 'utf8mb4'
};

// Pool de conexiones
const pool = mysql.createPool({
    ...dbConfig,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Clave secreta para JWT
const JWT_SECRET = process.env.JWT_SECRET || 'tu_clave_secreta_muy_segura';

// Middleware para validar errores
const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            message: 'Datos de entrada inválidos', 
            errors: errors.array() 
        });
    }
    next();
};

// Middleware para verificar JWT
const verifyToken = (roles = []) => {
    return async (req, res, next) => {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ success: false, message: 'Token no proporcionado' });
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
            
            if (roles.length > 0 && !roles.includes(decoded.tipo)) {
                return res.status(403).json({ success: false, message: 'Acceso denegado' });
            }
            
            next();
        } catch (error) {
            return res.status(401).json({ success: false, message: 'Token inválido' });
        }
    };
};

// ===================== RUTAS DE AUTENTICACIÓN =====================

// Login Turistas
app.post('/api/auth/turista/login', [
    body('email').isEmail().withMessage('Email inválido'),
    body('password').isLength({ min: 6 }).withMessage('Contraseña debe tener al menos 6 caracteres')
], validateRequest, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const [users] = await pool.execute(
            'SELECT id, nombre, apellido, email, password_hash, estado FROM turistas WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        const user = users[0];
        
        if (user.estado !== 'activo') {
            return res.status(401).json({ success: false, message: 'Cuenta inactiva' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, tipo: 'turista' },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Actualizar última conexión
        await pool.execute(
            'UPDATE turistas SET ultima_conexion = NOW() WHERE id = ?',
            [user.id]
        );

        res.json({
            success: true,
            message: 'Login exitoso',
            data: {
                token,
                user: {
                    id: user.id,
                    nombre: user.nombre,
                    apellido: user.apellido,
                    email: user.email
                }
            }
        });

    } catch (error) {
        console.error('Error en login turista:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Login Administradores de Negocio
app.post('/api/auth/admin/login', [
    body('email').isEmail().withMessage('Email inválido'),
    body('password').isLength({ min: 6 }).withMessage('Contraseña debe tener al menos 6 caracteres')
], validateRequest, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const [users] = await pool.execute(`
            SELECT an.id, an.negocio_id, an.nombre, an.apellido, an.email, 
                   an.password_hash, an.estado, an.permisos, n.nombre as nombre_negocio
            FROM administradores_negocios an
            INNER JOIN negocios n ON an.negocio_id = n.id
            WHERE an.email = ?
        `, [email]);

        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        const user = users[0];
        
        if (user.estado !== 'activo') {
            return res.status(401).json({ success: false, message: 'Cuenta inactiva' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email, 
                negocio_id: user.negocio_id,
                tipo: 'admin_negocio' 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        await pool.execute(
            'UPDATE administradores_negocios SET ultima_conexion = NOW() WHERE id = ?',
            [user.id]
        );

        res.json({
            success: true,
            message: 'Login exitoso',
            data: {
                token,
                user: {
                    id: user.id,
                    nombre: user.nombre,
                    apellido: user.apellido,
                    email: user.email,
                    negocio_id: user.negocio_id,
                    nombre_negocio: user.nombre_negocio,
                    permisos: user.permisos
                }
            }
        });

    } catch (error) {
        console.error('Error en login admin:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Login Super Administrador
app.post('/api/auth/super-admin/login', [
    body('usuario').isLength({ min: 3 }).withMessage('Usuario debe tener al menos 3 caracteres'),
    body('password').isLength({ min: 6 }).withMessage('Contraseña debe tener al menos 6 caracteres')
], validateRequest, async (req, res) => {
    try {
        const { usuario, password } = req.body;
        
        const [users] = await pool.execute(
            'SELECT id, usuario, nombre, email, password_hash, nivel_acceso, permisos FROM super_administradores WHERE usuario = ? AND estado = "activo"',
            [usuario]
        );

        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        const user = users[0];
        
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        const token = jwt.sign(
            { 
                id: user.id, 
                usuario: user.usuario, 
                tipo: 'super_admin',
                nivel_acceso: user.nivel_acceso
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        await pool.execute(
            'UPDATE super_administradores SET ultima_conexion = NOW() WHERE id = ?',
            [user.id]
        );

        res.json({
            success: true,
            message: 'Login exitoso',
            data: {
                token,
                user: {
                    id: user.id,
                    usuario: user.usuario,
                    nombre: user.nombre,
                    email: user.email,
                    nivel_acceso: user.nivel_acceso,
                    permisos: user.permisos
                }
            }
        });

    } catch (error) {
        console.error('Error en login super admin:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Registro de Turista
app.post('/api/auth/turista/register', [
    body('nombre').isLength({ min: 2 }).withMessage('Nombre debe tener al menos 2 caracteres'),
    body('apellido').isLength({ min: 2 }).withMessage('Apellido debe tener al menos 2 caracteres'),
    body('email').isEmail().withMessage('Email inválido'),
    body('password').isLength({ min: 6 }).withMessage('Contraseña debe tener al menos 6 caracteres')
], validateRequest, async (req, res) => {
    try {
        const { nombre, apellido, email, password, telefono, pais_origen, ciudad_origen } = req.body;
        
        // Verificar si el email ya existe
        const [existingUsers] = await pool.execute(
            'SELECT id FROM turistas WHERE email = ?',
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ success: false, message: 'El email ya está registrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const [result] = await pool.execute(`
            INSERT INTO turistas (nombre, apellido, email, password_hash, telefono, pais_origen, ciudad_origen) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [nombre, apellido, email, hashedPassword, telefono, pais_origen, ciudad_origen]);

        res.status(201).json({
            success: true,
            message: 'Turista registrado exitosamente',
            data: { id: result.insertId }
        });

    } catch (error) {
        console.error('Error en registro turista:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// ===================== RUTAS DE TURISTAS =====================

// Obtener perfil del turista
app.get('/api/turista/perfil', verifyToken(['turista']), async (req, res) => {
    try {
        const [users] = await pool.execute(`
            SELECT id, nombre, apellido, email, telefono, fecha_nacimiento, genero, 
                   pais_origen, ciudad_origen, preferencias_turisticas, foto_perfil, 
                   verificado, fecha_registro
            FROM turistas WHERE id = ?
        `, [req.user.id]);

        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        res.json({ success: true, data: users[0] });
    } catch (error) {
        console.error('Error al obtener perfil:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Actualizar perfil del turista
app.put('/api/turista/perfil', verifyToken(['turista']), [
    body('nombre').optional().isLength({ min: 2 }),
    body('apellido').optional().isLength({ min: 2 }),
    body('telefono').optional().isLength({ min: 10 })
], validateRequest, async (req, res) => {
    try {
        const { nombre, apellido, telefono, fecha_nacimiento, genero, pais_origen, ciudad_origen, preferencias_turisticas } = req.body;
        
        await pool.execute(`
            UPDATE turistas 
            SET nombre = COALESCE(?, nombre), apellido = COALESCE(?, apellido), 
                telefono = COALESCE(?, telefono), fecha_nacimiento = COALESCE(?, fecha_nacimiento),
                genero = COALESCE(?, genero), pais_origen = COALESCE(?, pais_origen),
                ciudad_origen = COALESCE(?, ciudad_origen), preferencias_turisticas = COALESCE(?, preferencias_turisticas)
            WHERE id = ?
        `, [nombre, apellido, telefono, fecha_nacimiento, genero, pais_origen, ciudad_origen, preferencias_turisticas, req.user.id]);

        res.json({ success: true, message: 'Perfil actualizado exitosamente' });
    } catch (error) {
        console.error('Error al actualizar perfil:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// ===================== RUTAS DE NEGOCIOS =====================

// Obtener todos los negocios (público)
app.get('/api/negocios', async (req, res) => {
    try {
        const { categoria, estado, limite = 50, pagina = 1 } = req.query;
        
        let query = `
            SELECT id, nombre, descripcion, direccion, telefono, email, categoria, 
                   latitud, longitud, horario_apertura, horario_cierre, dias_funcionamiento,
                   imagen_principal, sitio_web, calificacion_promedio, total_resenas, estado
            FROM negocios WHERE 1=1
        `;
        const params = [];

        if (categoria) {
            query += ' AND categoria = ?';
            params.push(categoria);
        }

        if (estado) {
            query += ' AND estado = ?';
            params.push(estado);
        }

        query += ' ORDER BY calificacion_promedio DESC, total_resenas DESC';
        query += ' LIMIT ? OFFSET ?';
        params.push(parseInt(limite), (parseInt(pagina) - 1) * parseInt(limite));

        const [negocios] = await pool.execute(query, params);

        res.json({ success: true, data: negocios });
    } catch (error) {
        console.error('Error al obtener negocios:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Obtener negocio por ID
app.get('/api/negocios/:id', async (req, res) => {
    try {
        const [negocios] = await pool.execute(`
            SELECT * FROM negocios WHERE id = ?
        `, [req.params.id]);

        if (negocios.length === 0) {
            return res.status(404).json({ success: false, message: 'Negocio no encontrado' });
        }

        res.json({ success: true, data: negocios[0] });
    } catch (error) {
        console.error('Error al obtener negocio:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Crear negocio (solo super admin)
app.post('/api/negocios', verifyToken(['super_admin']), [
    body('nombre').isLength({ min: 3 }).withMessage('Nombre debe tener al menos 3 caracteres'),
    body('email').isEmail().withMessage('Email inválido'),
    body('categoria').isIn(['restaurante', 'hotel', 'tienda', 'entretenimiento', 'servicios', 'otro'])
], validateRequest, async (req, res) => {
    try {
        const { nombre, descripcion, direccion, telefono, email, categoria, latitud, longitud, 
                horario_apertura, horario_cierre, dias_funcionamiento, sitio_web } = req.body;

        const [result] = await pool.execute(`
            INSERT INTO negocios 
            (nombre, descripcion, direccion, telefono, email, categoria, latitud, longitud,
             horario_apertura, horario_cierre, dias_funcionamiento, sitio_web, estado)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'activo')
        `, [nombre, descripcion, direccion, telefono, email, categoria, latitud, longitud,
            horario_apertura, horario_cierre, dias_funcionamiento, sitio_web]);

        res.status(201).json({
            success: true,
            message: 'Negocio creado exitosamente',
            data: { id: result.insertId }
        });
    } catch (error) {
        console.error('Error al crear negocio:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Actualizar negocio (admin del negocio o super admin)
app.put('/api/negocios/:id', verifyToken(['admin_negocio', 'super_admin']), async (req, res) => {
    try {
        const negocioId = req.params.id;
        
        // Verificar permisos
        if (req.user.tipo === 'admin_negocio' && req.user.negocio_id != negocioId) {
            return res.status(403).json({ success: false, message: 'Sin permisos para este negocio' });
        }

        const { nombre, descripcion, direccion, telefono, email, categoria, latitud, longitud,
                horario_apertura, horario_cierre, dias_funcionamiento, sitio_web } = req.body;

        await pool.execute(`
            UPDATE negocios 
            SET nombre = COALESCE(?, nombre), descripcion = COALESCE(?, descripcion),
                direccion = COALESCE(?, direccion), telefono = COALESCE(?, telefono),
                email = COALESCE(?, email), categoria = COALESCE(?, categoria),
                latitud = COALESCE(?, latitud), longitud = COALESCE(?, longitud),
                horario_apertura = COALESCE(?, horario_apertura), horario_cierre = COALESCE(?, horario_cierre),
                dias_funcionamiento = COALESCE(?, dias_funcionamiento), sitio_web = COALESCE(?, sitio_web)
            WHERE id = ?
        `, [nombre, descripcion, direccion, telefono, email, categoria, latitud, longitud,
            horario_apertura, horario_cierre, dias_funcionamiento, sitio_web, negocioId]);

        res.json({ success: true, message: 'Negocio actualizado exitosamente' });
    } catch (error) {
        console.error('Error al actualizar negocio:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// ===================== RUTAS DE RESEÑAS =====================

// Crear reseña (solo turistas)
app.post('/api/resenas', verifyToken(['turista']), [
    body('negocio_id').isInt({ min: 1 }),
    body('calificacion').isInt({ min: 1, max: 5 }),
    body('comentario').optional().isLength({ max: 1000 })
], validateRequest, async (req, res) => {
    try {
        const { negocio_id, calificacion, comentario } = req.body;

        // Verificar si ya existe una reseña
        const [existing] = await pool.execute(
            'SELECT id FROM resenas WHERE turista_id = ? AND negocio_id = ?',
            [req.user.id, negocio_id]
        );

        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: 'Ya has reseñado este negocio' });
        }

        const [result] = await pool.execute(`
            INSERT INTO resenas (turista_id, negocio_id, calificacion, comentario)
            VALUES (?, ?, ?, ?)
        `, [req.user.id, negocio_id, calificacion, comentario]);

        res.status(201).json({
            success: true,
            message: 'Reseña creada exitosamente',
            data: { id: result.insertId }
        });
    } catch (error) {
        console.error('Error al crear reseña:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Obtener reseñas de un negocio
app.get('/api/negocios/:id/resenas', async (req, res) => {
    try {
        const [resenas] = await pool.execute(`
            SELECT r.id, r.calificacion, r.comentario, r.fecha_creacion,
                   t.nombre, t.apellido
            FROM resenas r
            INNER JOIN turistas t ON r.turista_id = t.id
            WHERE r.negocio_id = ? AND r.estado = 'activa'
            ORDER BY r.fecha_creacion DESC
        `, [req.params.id]);

        res.json({ success: true, data: resenas });
    } catch (error) {
        console.error('Error al obtener reseñas:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// ===================== RUTAS DE ADMINISTRACIÓN =====================

// Crear administrador de negocio (solo super admin)
app.post('/api/admin/crear-admin-negocio', verifyToken(['super_admin']), [
    body('negocio_id').isInt({ min: 1 }),
    body('nombre').isLength({ min: 2 }),
    body('apellido').isLength({ min: 2 }),
    body('email').isEmail(),
    body('password').isLength({ min: 6 })
], validateRequest, async (req, res) => {
    try {
        const { negocio_id, nombre, apellido, email, password, telefono, cargo } = req.body;

        // Verificar si el email ya existe
        const [existing] = await pool.execute(
            'SELECT id FROM administradores_negocios WHERE email = ?',
            [email]
        );

        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: 'El email ya está registrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await pool.execute(`
            INSERT INTO administradores_negocios 
            (negocio_id, nombre, apellido, email, password_hash, telefono, cargo)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [negocio_id, nombre, apellido, email, hashedPassword, telefono, cargo]);

        res.status(201).json({
            success: true,
            message: 'Administrador de negocio creado exitosamente',
            data: { id: result.insertId }
        });
    } catch (error) {
        console.error('Error al crear admin negocio:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Obtener estadísticas generales (super admin)
app.get('/api/admin/estadisticas', verifyToken(['super_admin']), async (req, res) => {
    try {
        const [stats] = await pool.execute(`
            SELECT 
                (SELECT COUNT(*) FROM turistas WHERE estado = 'activo') as total_turistas,
                (SELECT COUNT(*) FROM negocios WHERE estado = 'activo') as total_negocios,
                (SELECT COUNT(*) FROM administradores_negocios WHERE estado = 'activo') as total_admins,
                (SELECT COUNT(*) FROM resenas WHERE estado = 'activa') as total_resenas,
                (SELECT AVG(calificacion_promedio) FROM negocios WHERE estado = 'activo') as calificacion_promedio_general
        `);

        res.json({ success: true, data: stats[0] });
    } catch (error) {
        console.error('Error al obtener estadísticas:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Obtener estadísticas del negocio (admin del negocio)
app.get('/api/negocio/estadisticas', verifyToken(['admin_negocio']), async (req, res) => {
    try {
        const [stats] = await pool.execute(`
            SELECT 
                n.nombre,
                n.calificacion_promedio,
                n.total_resenas,
                (SELECT COUNT(*) FROM resenas WHERE negocio_id = ? AND estado = 'activa' AND fecha_creacion >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as resenas_mes_actual
            FROM negocios n
            WHERE n.id = ?
        `, [req.user.negocio_id, req.user.negocio_id]);

        if (stats.length === 0) {
            return res.status(404).json({ success: false, message: 'Negocio no encontrado' });
        }

        res.json({ success: true, data: stats[0] });
    } catch (error) {
        console.error('Error al obtener estadísticas del negocio:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// ===================== RUTA DE VERIFICACIÓN DE SALUD =====================

app.get('/api/health', (req, res) => {
    res.json({ 
        success: true, 
        message: 'API funcionando correctamente',
        timestamp: new Date().toISOString()
    });
});

// Manejo de rutas no encontradas
app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Ruta no encontrada' });
});

// Manejo global de errores
app.use((error, req, res, next) => {
    console.error('Error global:', error);
    res.status(500).json({ success: false, message: 'Error interno del servidor' });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
    console.log(`Documentación disponible en: http://localhost:${PORT}/api/health`);
});

module.exports = app;