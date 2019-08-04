#!/bin/bash

#curl -X POST -d '{"email":"hoshoyo@gmail.com", "password":"helloworld"}' http://localhost:8888/v2/signup
#curl -X POST -d '{"email":"hoshoyo@gmail.com", "password":"helloworld"}' http://localhost:8888/v2/login

#WiKKcO8LNIXn3AWM61Zy-xr-4nooGeFzhyi8fMv0kjcYB_RWmHxgRa_IkGsPUHpyLDXF-86YI9_5I8wPgwOkag==
#curl -X POST -d '{"token":"WiKKcO8LNIXn3AWM61Zy-xr-4nooGeFzhyi8fMv0kjcYB_RWmHxgRa_IkGsPUHpyLDXF-86YI9_5I8wPgwOkag=="}' http://localhost:8888/v2/list

curl -X POST -d '{"email":"hoshoyo@gmail.com"}' http://localhost:8888/v2/resetpassword