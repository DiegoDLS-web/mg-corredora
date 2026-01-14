const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Iniciando seed...');

  // 1. Limpiar base de datos (para no duplicar si corres esto dos veces)
  try {
    await prisma.propiedad.deleteMany({});
    await prisma.usuario.deleteMany({});
  } catch (error) {
    console.log('Base de datos nueva, nada que borrar.');
  }

  // 2. Crear USUARIO ADMINISTRADOR
  // Contraseña: "admin123"
  const passwordEncriptada = await bcrypt.hash('admin123', 10);
  
  await prisma.usuario.create({
    data: {
      email: 'admin@mgpropiedades.cl',
      password: passwordEncriptada
    }
  });

  console.log('👤 Usuario Admin creado: admin@mgpropiedades.cl / admin123');

  // 3. Crear Propiedades de ejemplo
  const propiedades = [
    {
      titulo: "Casa estilo Mediterráneo en Lomas",
      operacion: "Venta",
      tipo: "Casa",
      precio: "UF 8.500",
      ubicacion: "Lomas de San Andrés",
      dormitorios: 4,
      banos: 3,
      imagen: "https://images.unsplash.com/photo-1564013799919-ab600027ffc6?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    },
    {
      titulo: "Departamento Vista al Río",
      operacion: "Arriendo",
      tipo: "Departamento",
      precio: "$450.000",
      ubicacion: "Concepción Centro",
      dormitorios: 2,
      banos: 1,
      imagen: "https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    }
  ];

  for (const p of propiedades) {
    await prisma.propiedad.create({ data: p });
  }
  
  console.log('✅ Base de datos cargada correctamente');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });