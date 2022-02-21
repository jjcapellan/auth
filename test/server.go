package authtest

import (
	"net/http"

	"github.com/gorilla/mux"
	jjauth "github.com/jjcapellan/auth"
)

// Server
func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("home"))
}

func membersHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("members"))
}

func vipHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("vip"))
}

func publicHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("public"))
}

func forbiddenHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("forbidden"))
}

func notlogedHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("notloged"))
}

func startServer() error {
	router := mux.NewRouter().StrictSlash(true)

	membersRouter := router.PathPrefix("/members").Subrouter()
	membersRouter.HandleFunc("/", membersHandler)
	membersRouter.Use(jjauth.GetAuthMiddleware(0, "/notlogedurl", "/forbiddenurl"))

	vipRouter := router.PathPrefix("/vip").Subrouter()
	vipRouter.HandleFunc("/", vipHandler)
	vipRouter.Use(jjauth.GetAuthMiddleware(4, "/notlogedurl", "/forbiddenurl"))

	router.HandleFunc("/", rootHandler)
	router.HandleFunc("/public/", publicHandler)
	router.HandleFunc("/notlogedurl", notlogedHandler)
	router.HandleFunc("/forbiddenurl", forbiddenHandler)

	err := http.ListenAndServe(":3000", router)
	if err != nil {
		return err
	}
	return nil
}
