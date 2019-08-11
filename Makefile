run-dev:
	./start_dev.sh

run-prod: build
	./start.sh

docker-run:
	docker-compose up

docker-build: docker-build-db docker-build-api

docker-build-db:
	docker build --no-cache -t hoshoyo/shapass-db:latest -f Dockerfile.postgres .

docker-build-api:
	docker build -t hoshoyo/shapass:latest -f Dockerfile.api .

build:
	go build src/*.go

rundb-dev:
	docker run --rm -ti -p 5555:5432 hoshoyo/shapass-db:latest