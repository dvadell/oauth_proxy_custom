# OAuth Proxy Custom

A simple, self-hosted authentication proxy to protect your applications.

## Features

- User authentication with password strength policies.
- Forced password change on first login.
- Brute-force protection with account lockout.
- Integration with Nginx's `auth_request` module.
- Production-ready setup with Docker and Gunicorn.

## Prerequisites

- Docker
- Docker Compose

## Local Development

To run the application in a local development environment, follow these steps:

1.  **Build the Docker image:**
    ```bash
    docker-compose build
    ```

2.  **Initialize the database:**
    This command will create the database schema in a Docker volume. It only needs to be run once.
    ```bash
    docker-compose run --rm auth-app flask init-db
    ```

3.  **Start the application:**
    ```bash
    docker-compose up -d
    ```
    The application will be available at `http://localhost:7906`.

## Production Deployment

This application is designed to be deployed using Docker. The `docker-compose.prod.yml` file is configured to use a pre-built Docker image from a container registry.

### 1. Build and Push the Docker Image

The production setup relies on a Docker image hosted in a registry (e.g., GitHub Container Registry, Docker Hub). The `.github/workflows/docker.yml` file provides an example of how to build and push the image automatically with GitHub Actions.

You will need to configure your own repository and registry to store the image.

### 2. Configure the Production Environment

On your production server, you will need the `docker-compose.prod.yml` file. Before starting the application, you must edit this file and change the `SECRET_KEY` environment variable to a strong, unique secret.

```yaml
services:
  auth-app:
    image: ghcr.io/dvadell/oauth_proxy_custom:latest # Change this to your image if needed
    ...
    environment:
      ...
      - SECRET_KEY=__CHANGE_ME__ # <-- CHANGE THIS
```

### 3. First-Time Deployment

For a new, first-time deployment, follow these steps on your production server:

1.  **Pull the latest image:**
    ```bash
    docker-compose -f docker-compose.prod.yml pull
    ```

2.  **Initialize the Production Database:**
    This command will create the database schema in the production Docker volume.

    **⚠️ Warning:** Run this command **only once** for a new deployment. Do not run it on an existing database.
    ```bash
    docker-compose -f docker-compose.prod.yml run --rm auth-app flask init-db
    ```

3.  **Start the Application:**
    ```bash
    docker-compose -f docker-compose.prod.yml up -d
    ```

### 4. Future Updates and Migrations

The `init-db` command is only for the initial setup. For future updates that require changes to the database schema (e.g., adding a new column), you will need a proper database migration strategy. Using a tool like `Flask-Migrate` is highly recommended for this purpose to ensure data is not lost during updates.