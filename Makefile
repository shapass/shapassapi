run:
	go run main.go utils.go api.go
build:
	docker build -t hoshoyo/shapass:dblatest -f Dockerfile.postgres .
	go build main.go utils.go api.go
rundb:
	docker run -ti -p 5432:5432 hoshoyo/shapass:dblatest
