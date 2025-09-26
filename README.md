# Flujo del Pipeline
- **Construcción:** crear la imagen Docker de la aplicación.  
- **Publicación:** subir la imagen a un registro de contenedores (ej. Docker Hub o Amazon ECR).  
- **Despliegue:** conectarse por SSH a una instancia EC2 o VM, descargar la imagen y levantar el contenedor.  
- **Migraciones:** ejecutar migraciones de base de datos al terminar el despliegue.  

---

## Ejemplo de GitHub Actions Workflow

Archivo: `.github/workflows/deploy.yml`

```yaml
name: CI/CD Pipeline

on:
  push:
    branches:
      - develop   # Solo corre cuando se hace merge a develop

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest

    steps:
      # 1. Clonar repo
      - name: Checkout code
        uses: actions/checkout@v3

      # 2. Loguearse en Docker Hub (usa Secrets de GitHub)
      - name: Log in to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}

      # 3. Construir imagen Docker
      - name: Build Docker image
        run: |
          docker build -t ${{ secrets.DOCKERHUB_USERNAME }}/mi-app:latest .

      # 4. Publicar en Docker Hub
      - name: Push Docker image
        run: |
          docker push ${{ secrets.DOCKERHUB_USERNAME }}/mi-app:latest

      # 5. Despliegue en EC2
      - name: Deploy to EC2
        uses: appleboy/ssh-action@v1.0.0
        with:
          host: ${{ secrets.EC2_HOST }}
          username: ubuntu
          key: ${{ secrets.EC2_SSH_KEY }}
          script: |
            docker pull ${{ secrets.DOCKERHUB_USERNAME }}/mi-app:latest
            docker stop mi-app || true
            docker rm mi-app || true
            docker run -d --name mi-app -p 80:80 ${{ secrets.DOCKERHUB_USERNAME }}/mi-app:latest

      # 6. Migraciones de base de datos
      - name: Run DB migrations
        uses: appleboy/ssh-action@v1.0.0
        with:
          host: ${{ secrets.EC2_HOST }}
          username: ubuntu
          key: ${{ secrets.EC2_SSH_KEY }}
          script: |
            docker exec mi-app npm run migrate   # O el comando de migraciones de tu framework
```

---

##Secrets necesarios en GitHub

En el repositorio, vamos a Settings → Secrets and variables → Actions y agregamos:

`DOCKERHUB_USERNAME` → usuario de Docker Hub

`DOCKERHUB_TOKEN` → token de acceso a Docker Hub

`EC2_HOST` → IP pública de la instancia EC2

`EC2_SSH_KEY` → clave privada SSH para conectarse al servidor

Este pipeline automatiza el ciclo de vida de la aplicación en cuatro fases principales:

- **Build:** GitHub Actions crea una imagen Docker con el código actualizado.

- **Push:** La imagen se publica en Docker Hub para centralizar la distribución.

- **Deploy:** Desde GitHub Actions se accede vía SSH a una instancia EC2, se descarga la nueva imagen, se detiene la versión anterior y se levanta el nuevo contenedor.

- **Migrate:** Una vez desplegado el contenedor, se ejecutan los comandos de migración de base de datos para aplicar cambios de esquema o actualizaciones pendientes.

---

## Migraciones de base de datos

Las migraciones se manejan ejecutando un comando dentro del contenedor recién desplegado.
Esto garantiza que:

- Siempre se apliquen después del despliegue y no antes.

- El estado de la base de datos esté sincronizado con la versión actual del código.

- el comando correspondiente se corre directamente dentro del contenedor usando:

`docker exec mi-app <comando-de-migraciones>`
