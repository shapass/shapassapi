run-prod:
	./main
build-prod:
	go build main.go utils.go api.go


run-dev:
	go run main.go utils.go api.go
build-dev:
	docker build -t hoshoyo/shapass:dblatest -f Dockerfile.postgres .
	go build main.go utils.go api.go
rundb-dev:
	docker run -ti -p 5555:5432 hoshoyo/shapass:dblatest
