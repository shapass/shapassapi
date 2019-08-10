#!/bin/bash

curl -X POST -d '{"email":"hoshoyo@gmail.com", "password":"foo"}' http://localhost:8000/signup
curl -X POST -d '{"email":"hoshoyo@gmail.com", "password":"foo"}' http://localhost:8000/login