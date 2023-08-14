package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Hardcorelevelingwarrior/chap3/internal"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-chi/chi/v5/middleware"
)
type Chirp struct {
	Id int `json:"id,omitempty"`
	Body string `json:"body,omitempty"`
	
}

func main() {
	db, _ := internal.NewDB("database.json")
	cfg := apiConfig{}
	port := "8080"
	//mux := http.NewServeMux()
	r := chi.NewRouter()
	fsHandler := cfg.middlewareMetricsInc(http.StripPrefix("/app",http.FileServer(http.Dir("."))))
	r.Handle("/app/*",fsHandler)
	r.Handle("/app",fsHandler)

	c := chi.NewRouter()
	d := chi.NewRouter()
	c.Get("/healthz", func(w http.ResponseWriter, r *http.Request){
		w.WriteHeader(200)
		w.Header().Add("Content-Type","text/plain; charset=utf-8")
		w.Write([]byte("OK"))
	})
	c.Post("/chirps",func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		newchirp := Chirp{}
		err := decoder.Decode(&newchirp)
		if err != nil {
			panic(err)
		}
		db.CreateChirp(newchirp.Body)
		re , _ := json.Marshal(newchirp)
		w.Write(re)
	})
	c.Get("/chirps",func(w http.ResponseWriter, r *http.Request) {
		data , _ := db.GetChirps()
		jsonData, err := json.Marshal(data)
		if err != nil {
			panic(err)
		}
		w.Write(jsonData)
	})

	c.Get( "/chirps/{chirpID}" ,func(w http.ResponseWriter, r *http.Request) {
		chirpID, err := strconv.Atoi(chi.URLParam(r, "chirpID"))
	if err != nil {
		http.Error(w, http.StatusText(400), 400)
		return
	}
	data , _ := db.GetChirpsById(chirpID)
	if data.Body == "" {
		w.WriteHeader(404)
		return
	}
	re, _ := json.Marshal(data)
	w.Write(re)
	})
	c.Post("/users",func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		newusers := internal.User{}
		err := decoder.Decode(&newusers)
		if err != nil {
			panic(err)
		}
		usersforshow := internal.User{
			Id: newusers.Id,
			Email: newusers.Email,
		}
		_, er := db.CreateUser(newusers.Email,newusers.Password)
		if er != nil {fmt.Println(er)}
		re , _ := json.Marshal(usersforshow)
		w.WriteHeader(201)
		w.Write(re)
	})
	c.Post("/login",func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		newusers := internal.User{}
		err := decoder.Decode(&newusers)
		if err != nil {
			panic(err)
		}
		usersforshow := internal.User{
			Id: newusers.Id,
			Email: newusers.Email,
		}
		_ , er := db.GetUserbyEmail(newusers.Email,newusers.Password)
		if er != nil {
			fmt.Println(er)
			w.WriteHeader(401)
			return

		}
		re , _ := json.Marshal(usersforshow)
		w.WriteHeader(201)
		w.Write(re)
	})
	d.Get("/metrics", func (w http.ResponseWriter , r *http.Request){
		w.Header().Add("Content-Type","text/html")

		w.Write([]byte(fmt.Sprintf("Hits : %v",cfg.fileserverHits) ))
	})
	r.Mount("/api",c)
	r.Mount("/admin",d)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := ioutil.ReadFile("index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		content := strings.ReplaceAll(string(data), "%d", fmt.Sprintf("%d", cfg.fileserverHits))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(content))
	})
	corsMux := middlewareCors(r)

	srv := &http.Server {
		Addr : ":" + port,
		Handler: corsMux,
	}
	log.Fatal(srv.ListenAndServe())
	
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type apiConfig struct {
	fileserverHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	
	return http.HandlerFunc(func (w http.ResponseWriter , r *http.Request){
		next.ServeHTTP(w, r)
		cfg.fileserverHits ++
	})
}

