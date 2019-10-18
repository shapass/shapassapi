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

install: build
	sudo cp shapassapi /usr/bin/shapassapi
	sudo cp shapassapi.service /lib/systemd/system/shapassapi.service
	sudo cp .env /etc/default/shapassenv
	sudo systemctl enable shapassapi
	sudo systemctl daemon-reload
reload:
	sudo systemctl stop shapassapi
	sudo cp shapassapi /usr/bin/shapassapi
	sudo systemctl start shapassapi

build:
	go build -o shapassapi src/*.go

rundb-dev:
	docker run --rm -ti -p 5555:5432 hoshoyo/shapass-db:latest
