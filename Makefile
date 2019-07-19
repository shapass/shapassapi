run-prod:
	./main
build-prod:
	go build main.go utils.go api.go
run-dev:
	go run main.go utils.go api.go
build-dev:
	go build main.go utils.go api.go
rundb-dev:
	docker run -ti -p 5555:5432 hoshoyo/shapass-db:latest
docker-build:
	docker build -t hoshoyo/shapass:latest -f Dockerfile.api .
	docker build -t hoshoyo/shapass-db:latest -f Dockerfile.postgres .