package main

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Hardcorelevelingwarrior/chap3/booking"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// JWTClaims represents the claims for JWT token
type JWTClaims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	jwt.StandardClaims
}

// OwnerJWTClaims represents the claims for JWT token specific to owners
type OwnerJWTClaims struct {
	OwnerID int    `json:"owner_id"`
	Email   string `json:"email"`
	jwt.StandardClaims
}

type apiConfig struct {
	jwtSecret string
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}

	apiCfg := apiConfig{
		jwtSecret: jwtSecret,
	}
	db, err := booking.NewDB("database.json")
	if err != nil {
		log.Fatalf("Error creating database: %v", err)
	}

	r := chi.NewRouter()
	r.Get("/",MainHTMLHandler)

	r.Post("/register_owner", RegisterOwnerHandler(db))
	r.Get("/register_owner", RegisterOwnerHTMLHandler)
	r.Get("/login/owner",OwnerLoginHTMLHandler)
	r.Post("/login/owner", OwnerLoginHandler(db,apiCfg))

	r.Post("/register/playground", RegisterPlaygroundHandler(db,apiCfg))
	r.Get("/register/playground", ResPlayHTMLHandler)
	r.Get("/playgrounds", GetPlaygroundsHandler(db))
	r.Get("/playgrounds/{id}", GetPlaygroundHandler(db))
	//r.Delete("/playgrounds/{id}", DeletePlaygroundHandler(db, apiCfg))


	r.Post("/register_user", RegisterUserHandler(db))
	r.Get("/register_user", RegisterUserHTMLHandler)
	r.Get("/login/user",LoginUserHTMLHandler)
	r.Post("/login/user", UserLoginHandler(db, apiCfg))
	//r.Put("/users",UpdateUserHandler(db,apiCfg))

	r.Post("/booking", BookPlaygroundHandler(db, apiCfg))
	r.Get("/booking",BookingHTMLHandler)
	r.Get("/login",LoginHTMLHandler)
	log.Println("Server started on port 8080")
	http.ListenAndServe(":8080", r)
}
func BookingHTMLHandler(w http.ResponseWriter, r *http.Request) {
    // Read the HTML file
    htmlData, err := ioutil.ReadFile("booking.html")
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Set the Content-Type header
    w.Header().Set("Content-Type", "text/html")

    // Write the HTML response
    w.Write(htmlData)
}
func OwnerLoginHTMLHandler(w http.ResponseWriter, r *http.Request) {
    // Read the HTML file
    htmlData, err := ioutil.ReadFile("login_owner.html")
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Set the Content-Type header
    w.Header().Set("Content-Type", "text/html")

    // Write the HTML response
    w.Write(htmlData)
}

func MainHTMLHandler(w http.ResponseWriter, r *http.Request) {
    // Read the HTML file
    htmlData, err := ioutil.ReadFile("main.html")
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Set the Content-Type header
    w.Header().Set("Content-Type", "text/html")

    // Write the HTML response
    w.Write(htmlData)
}
func ResPlayHTMLHandler(w http.ResponseWriter, r *http.Request) {
    // Read the HTML file
    htmlData, err := ioutil.ReadFile("res_playground.html")
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Set the Content-Type header
    w.Header().Set("Content-Type", "text/html")

    // Write the HTML response
    w.Write(htmlData)
}
func LoginUserHTMLHandler(w http.ResponseWriter, r *http.Request) {
    // Read the HTML file
    htmlData, err := ioutil.ReadFile("login_user.html")
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        log.Println("Failed to read HTML file:", err)
        return
    }

    // Set the Content-Type header
    w.Header().Set("Content-Type", "text/html")

    // Write the HTML response
    w.Write(htmlData)
}

func LoginHTMLHandler(w http.ResponseWriter, r *http.Request) {
    // Read the HTML file
    htmlData, err := ioutil.ReadFile("login.html")
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        log.Println("Failed to read HTML file:", err)
        return
    }

    // Set the Content-Type header
    w.Header().Set("Content-Type", "text/html")

    // Write the HTML response
    w.Write(htmlData)
}

func RegisterOwnerHandler(db *booking.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse form data from the request
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			log.Println("Failed to parse form data:", err)
			return
		}

		// Extract owner data from the form
		name := r.FormValue("name")
		email := r.FormValue("email")
		password := r.FormValue("password")
		phone := r.FormValue("phone")
		location := r.FormValue("location")

		// Check if required fields are empty
		if name == "" || email == "" || password == "" {
			http.Error(w, "Name, email, and password are required", http.StatusBadRequest)
			log.Println("Name, email, and password are required")
			return
		}

		// Check if owner with the same email already exists
		_, err = db.GetOwnerByEmail(email)
		if err == nil {
			http.Error(w, "Owner with this email already exists", http.StatusConflict)
			log.Println("Owner with this email already exists")
			return
		}

		// Create the owner
		_, err = db.CreateOwner(name, email, password, phone, location)
		if err != nil {
			http.Error(w, "Failed to register owner. Please try again.", http.StatusInternalServerError)
			log.Println("Failed to register owner:", err)
			return
		}

		// Redirect the user to a success page or perform any other action
		http.Redirect(w, r, "/registration-successful.html", http.StatusSeeOther)
	}
}



func RegisterUserHTMLHandler(w http.ResponseWriter, r *http.Request) {
    // Read the HTML file
    htmlData, err := ioutil.ReadFile("register_user.html")
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        log.Println("Failed to read HTML file:", err)
        return
    }

    // Set the Content-Type header
    w.Header().Set("Content-Type", "text/html")

    // Write the HTML response
    w.Write(htmlData)
}
func RegisterOwnerHTMLHandler(w http.ResponseWriter, r *http.Request) {
    // Read the HTML file
    htmlData, err := ioutil.ReadFile("register_owner.html")
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        log.Println("Failed to read HTML file:", err)
        return
    }

    // Set the Content-Type header
    w.Header().Set("Content-Type", "text/html")

    // Write the HTML response
    w.Write(htmlData)
}



func RegisterUserHandler(db *booking.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse form data from the request
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			log.Println("Failed to parse form data:", err)
			return
		}

		// Extract user data from the form
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Check if required fields are empty
		if email == "" || password == "" {
			http.Error(w, "Email and password are required", http.StatusBadRequest)
			log.Println("Email and password are required")
			return
		}

		// Check if user with the same email already exists
		_, err = db.GetUserByEmail(email)
		if err == nil {
			http.Error(w, "User with this email already exists", http.StatusConflict)
			return
		}

		// Create the new user
		_, err = db.CreateUser(email, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println("Failed to create user:", err)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}


func RegisterPlaygroundHandler(db *booking.DB, cfg apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the JWT token from the request cookies
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Missing token cookie", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Failed to get token from cookie", http.StatusBadRequest)
			return
		}

		tokenString := cookie.Value

		// Validate the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.jwtSecret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract owner ID from the token claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		ownerIDFloat64, ok := claims["owner_id"].(float64)
		if !ok {
			http.Error(w, "Invalid owner ID in token claims", http.StatusUnauthorized)
			return
		}

		ownerID := int(ownerIDFloat64)

		// Check if the owner exists
		_, err = db.GetOwnerByID(ownerID)
		if err != nil {
			http.Error(w, "Owner not found", http.StatusUnauthorized)
			return
		}

		// Parse form data from the request
		err = r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		// Extract playground data from the form
		name := r.FormValue("name")
		location := r.FormValue("location")
		size := r.FormValue("size")
		availableHours := r.FormValue("available_hours")
		cancellation_period := r.FormValue("cancellation_period")
		price_per_hour := r.FormValue("price_per_hour")
		price_per_hour_float ,_ := strconv.ParseFloat(strings.TrimSpace(price_per_hour), 64)
		cancellation_period_int,_  := strconv.Atoi(cancellation_period)
		// Create the playground
		_, err = db.CreatePlayground(ownerID, booking.Playground{
			Name:        name,
			Location:    location,
			Size:      size,
			AvailableHours: availableHours,
			CancellationPeriod: cancellation_period_int,
			PricePerHour: price_per_hour_float,
			OwnerID: ownerID,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}


func GetPlaygroundsHandler(db *booking.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		playgrounds, err := db.GetAllPlaygrounds()
		if err != nil {
			http.Error(w, "Failed to get playgrounds: "+err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl, err := template.ParseFiles("playgrounds.html")
		if err != nil {
			http.Error(w, "Failed to parse HTML template: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, playgrounds)
		if err != nil {
			http.Error(w, "Failed to execute HTML template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func GetPlaygroundHandler(db *booking.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "Invalid playground ID: "+err.Error(), http.StatusBadRequest)
			return
		}

		playground, err := db.GetPlaygroundByID(id)
		if err != nil {
			http.Error(w, "Failed to get playground: "+err.Error(), http.StatusNotFound)
			return
		}

		tmpl, err := template.ParseFiles("playground.html")
		if err != nil {
			http.Error(w, "Failed to parse HTML template: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, playground)
		if err != nil {
			http.Error(w, "Failed to execute HTML template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}


func UserLoginHandler(db *booking.DB, cfg apiConfig) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Parse form data from the request
        err := r.ParseForm()
        if err != nil {
            http.Error(w, "Failed to parse form data", http.StatusBadRequest)
            log.Println("Failed to parse form data:", err)
            return
        }

        // Extract login information from the form
        email := r.FormValue("email")
		log.Println(email)
        password := r.FormValue("password")

        // Retrieve user from the database using the provided email
        user, err := db.GetUserByEmail(email)
        if err != nil {
            http.Error(w, "Invalid email or password", http.StatusUnauthorized)
            log.Println("Invalid email or password:", err)
            return
        }

        // Compare the provided password with the stored password hash
        err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
        if err != nil {
            http.Error(w, "Invalid email or password", http.StatusUnauthorized)
            log.Println("Invalid email or password:", err)
            return
        }

        // Calculate token expiration time
        expiresAt := time.Now().UTC().Add(24 * time.Hour) // Default expiration time: 24 hours

        // Create JWT token
        token := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
            UserID: user.ID,
            Email:  user.Email,
            StandardClaims: jwt.StandardClaims{
                Issuer:    "chirpy",
                IssuedAt:  time.Now().UTC().Unix(),
                ExpiresAt: expiresAt.Unix(),
            },
        })

        // Sign the token with the JWT secret
        tokenString, err := token.SignedString([]byte(cfg.jwtSecret))
        if err != nil {
            http.Error(w, "Failed to generate token", http.StatusInternalServerError)
            return
        }

		// Set the token as a cookie in the HTTP response
		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expiresAt,	Path: "/", MaxAge: 86400, HttpOnly: true, Secure: true,

		})

        http.Redirect(w, r, "/", http.StatusSeeOther)
    }
}


	
func OwnerLoginHandler(db *booking.DB, cfg apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse form data from the request
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			log.Println("Failed to parse form data:", err)
			return
		}

		// Extract login information from the form
		email := r.FormValue("email")
		password := r.FormValue("password")

		owner, err := db.GetOwnerByEmail(email)
		if err != nil {
			http.Error(w, "Owner not found", http.StatusUnauthorized)
			log.Println("Owner not found:", err)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(owner.Password), []byte(password))
		if err != nil {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
			log.Println("Invalid email or password:", err)
			return
		}

		// Calculate token expiration time
		expiresAt := time.Now().UTC().Add(24 * time.Hour) // Default expiration time: 24 hours

		// Create JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, OwnerJWTClaims{
			OwnerID: owner.ID,
			Email:   owner.Email,
			StandardClaims: jwt.StandardClaims{
				Issuer:    "chirpy",
				IssuedAt:  time.Now().UTC().Unix(),
				ExpiresAt: expiresAt.Unix(),
			},
		})

		// Sign the token with the JWT secret
		tokenString, err := token.SignedString([]byte(cfg.jwtSecret))
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			log.Println("Failed to generate token:", err)
			return
		}

		// Set the token as a cookie in the HTTP response
		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expiresAt,
			Path: "/", MaxAge: 86400, HttpOnly: true, Secure: true,
		})

        http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}


func UpdateUserHandler(db *booking.DB, cfg apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the JWT token from the request headers
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Validate the JWT token and extract claims
		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.jwtSecret), nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract the user's ID from the JWT claims
		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		// Decode the request body
		var updateParams struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&updateParams); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Update the user in the database
		updatedUser, err := db.UpdateUser(claims.UserID, updateParams.Email, updateParams.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Return the updated user resource
		response := struct {
			ID    int    `json:"id"`
			Email string `json:"email"`
		}{
			ID:    updatedUser.ID,
			Email: updatedUser.Email,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func DeletePlaygroundHandler(db *booking.DB, cfg apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the JWT token from the request headers
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Validate the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.jwtSecret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract owner ID from the token claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		ownerIDFloat64, ok := claims["owner_id"].(float64)
		if !ok {
			http.Error(w, "Invalid owner ID in token claims", http.StatusUnauthorized)
			return
		}

		ownerID := int(ownerIDFloat64)

		// Extract playground ID from the URL parameter
		playgroundID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			http.Error(w, "Invalid playground ID", http.StatusBadRequest)
			return
		}

		// Check if the playground belongs to the authenticated owner
		playground, err := db.GetPlaygroundByID(playgroundID)
		if err != nil {
			http.Error(w, "Playground not found", http.StatusNotFound)
			return
		}

		if playground.OwnerID != ownerID {
			http.Error(w, "Unauthorized: Playground does not belong to the authenticated owner", http.StatusUnauthorized)
			return
		}

		// Delete the playground
		err = db.DeletePlayground(playgroundID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func BookPlaygroundHandler(db *booking.DB, cfg apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the JWT token from the request cookies
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Missing token cookie", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Failed to get token from cookie", http.StatusBadRequest)
			return
		}

		tokenString := cookie.Value

		// Validate the JWT token and extract claims
		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.jwtSecret), nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract the user's ID from the JWT claims
		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		// Parse form data to get booking details
		err = r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		playgroundIDStr := r.Form.Get("playground_id")
		playgroundID, err := strconv.Atoi(playgroundIDStr)
		if err != nil {
			http.Error(w, "Invalid playground ID", http.StatusBadRequest)
			return
		}

		startTimeString := r.Form.Get("start_time")
		startTime, err := time.Parse("2006-01-02T15:04", startTimeString)
		if err != nil {
			http.Error(w, "Invalid start time", http.StatusBadRequest)
			return
		}
		

		durationStr := r.Form.Get("duration")
		duration, err := strconv.Atoi(durationStr)
		if err != nil {
			http.Error(w, "Invalid duration", http.StatusBadRequest)
			return
		}

		// Validate the booking request
		if startTime.Before(time.Now()) {
			http.Error(w, "Booking start time must be in the future", http.StatusBadRequest)
			return
		}

		if duration <= 0 {
			http.Error(w, "Booking duration must be greater than zero", http.StatusBadRequest)
			return
		}

		// Check if the playground exists
		_, err = db.GetPlaygroundByID(playgroundID)
		if err != nil {
			http.Error(w, "Playground not found", http.StatusNotFound)
			return
		}

		// Calculate end time based on duration
		endTime := startTime.Add(time.Duration(duration) * time.Hour)

		// Check if the requested time slot is available
		bookings, err := db.GetBookingsForPlayground(playgroundID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		for _, booking := range bookings {
			if !(endTime.Before(booking.StartTime) || startTime.After(booking.EndTime)) {
				http.Error(w, "Requested time slot is not available", http.StatusConflict)
				return
			}
		}

		// Create the booking
		_, err = db.CreateBooking(claims.UserID, playgroundID, startTime, endTime)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}


