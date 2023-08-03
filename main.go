package main

import (
	"fmt"
	"net/http"
)


func main() {
	cfg := apiConfig{}
	port := "8080"
	mux := http.NewServeMux()
	mux.Handle("/app/",http.StripPrefix("/app",cfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request){
		w.Write([]byte("OK"))
		w.WriteHeader(200)
		w.Header().Add("Content-Type","text/plain; charset=utf-8")
	})
	mux.HandleFunc("/metrics", func (w http.ResponseWriter , r *http.Request){

		w.Write([]byte(fmt.Sprintf("Hits : %v",cfg.fileserverHits) ))
	})

	corsMux := middlewareCors(mux)

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

