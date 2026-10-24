# Convenience wrappers. `make up` / `make down` / `make ps` / `make logs`.
.PHONY: up down ps logs

up:
	./up.sh

down:
	./down.sh

ps:
	podman-compose -p nexus-postgres  -f compose.postgres.yml  ps
	podman-compose -p nexus-qdrant    -f compose.qdrant.yml    ps
	podman-compose -p nexus-redis     -f compose.redis.yml     ps
	podman-compose -p nexus-ordinario -f compose.ordinario.yml ps

logs:
	podman logs -f wl_app