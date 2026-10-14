# Receptor genérico de eventos de prueba

POC de Mastria. Node.js y Postgres, con validación de eventos, IDs únicos, CORS acotado y consola protegida.

Configuración requerida por variables de entorno: ADMIN_PASSWORD, ALLOWED_ORIGIN, ALLOWED_SITE_ID, ALLOWED_COURSE_ID y DATABASE_URL en producción. Opcional ALLOWED_PAGE_PREFIX, PORT.

Este repo no contiene configuración de clientes, datos de usuarios, eventos, videos ni credenciales. El receptor no verifica la identidad de alumnos: los eventos son reportes del navegador.

Build: npm install --omit=dev. Inicio: node server.mjs.
