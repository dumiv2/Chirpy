package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

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

	c := chi.NewRouter()
	d := chi.NewRouter()
	c.Get("/healthz", func(w http.ResponseWriter, r *http.Request){
		w.WriteHeader(200)
		w.Header().Add("Content-Type","text/plain; charset=utf-8")
		w.Write([]byte("OK"))
	})
	c.Post("/validate_chirp",func(w http.ResponseWriter, r *http.Request) {
		type chirp struct {
			Body string `json:"body"`
		}
		type validate struct {
			Err string `json:"error,omitempty"`
			Valid bool `json:"valid,omitempty"`
			Cleanbody string `json:"cleaned_body,omitempty"`
		}
		validate_chirp := validate{
			Valid : true,
		}
		dat , _:= json.Marshal(validate_chirp)
		decoder := json.NewDecoder(r.Body)
		chirpee := chirp{}
		err := decoder.Decode(&chirpee)
		
		if err != nil {
			validate_chirp := validate{
				Err : "Cannot marshaling" ,
			}
			dat,_ := json.Marshal(validate_chirp)
			w.WriteHeader(400)
			w.Write(dat)
			return
		}
		if len(chirpee.Body) > 140 {
			validate_chirp := validate{
				Err : "Chirp is too long" ,
			}
			dat,_ := json.Marshal(validate_chirp)
			w.WriteHeader(400)
			w.Write(dat)
			return
		}
		w.Write(dat)
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

