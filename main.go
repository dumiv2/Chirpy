package main

import (
	"fmt"
	"net/http"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-chi/chi/v5/middleware"
)


func main() {
	cfg := apiConfig{}
	port := "8080"
	//mux := http.NewServeMux()
	r := chi.NewRouter()
	fsHandler := cfg.middlewareMetricsInc(http.StripPrefix("/app",http.FileServer(http.Dir("."))))
	r.Handle("/app/*",fsHandler)
	r.Handle("/app",fsHandler)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request){
		w.Write([]byte("OK"))
		w.WriteHeader(200)
		w.Header().Add("Content-Type","text/plain; charset=utf-8")
	})
	r.Get("/metrics", func (w http.ResponseWriter , r *http.Request){

		w.Write([]byte(fmt.Sprintf("Hits : %v",cfg.fileserverHits) ))
	})

	corsMux := middlewareCors(r)

	srv := &http.Server {
		Addr : ":" + port,
		Handler: corsMux,
	}
	srv.ListenAndServe()
	
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

