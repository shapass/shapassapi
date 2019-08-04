run-dev:
	go run src/*.go

docker-run:
	docker-compose up

docker-build:
	docker build -t hoshoyo/shapass:latest -f Dockerfile.api .
	docker build -t hoshoyo/shapass-db:latest -f Dockerfile.postgres .

build:
	go build src/*.go

rundb-dev:
	docker run -ti -p 5555:5432 hoshoyo/shapass-db:latest