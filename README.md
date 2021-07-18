- **Docker-Compose Commands:**
  - Create what is necessary and start detatched:
    - docker-compose up -d
  - Force rebuild and start detached:
    - docker-compose up --build -d
  - Stop services:
    - docker-compose stop
  - Stop services and remove containers and data volumes.
    - docker-compose down --volumes


- **Docker Commands:**
  - Delete ALL unused images:
    - docker image prune --all
