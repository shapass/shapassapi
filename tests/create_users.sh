#!/bin/bash

curl -X POST -d '{"email":"foo1@bar.com", "password":"foo1"}' http://localhost:8888/v2/signup
curl -X POST -d '{"email":"foo2@bar.com", "password":"foo2"}' http://localhost:8888/v2/signup
curl -X POST -d '{"email":"foo3@bar.com", "password":"foo3"}' http://localhost:8888/v2/signup
curl -X POST -d '{"email":"foo4@bar.com", "password":"foo4"}' http://localhost:8888/v2/signup
curl -X POST -d '{"email":"foo5@bar.com", "password":"foo5"}' http://localhost:8888/v2/signup