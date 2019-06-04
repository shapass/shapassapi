run:
	go run main.go utils.go
build:
	docker build -t hoshoyo/shapass:dblatest -f Dockerfile.postgres .
rundb:
	docker run -ti -p 5432:5432 hoshoyo/shapass:dblatest