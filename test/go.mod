module github.com/jjcapellan/auth/testing

go 1.16

replace github.com/jjcapellan/auth => ../

require (
	github.com/gorilla/mux v1.8.0
	github.com/jjcapellan/auth v1.0.0-alpha.1
	github.com/mattn/go-sqlite3 v1.14.11
)
