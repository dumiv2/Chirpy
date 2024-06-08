package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"path/filepath"
	"regexp"
	"sync"
	"unicode"

	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Hardcorelevelingwarrior/chap3/booking"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator"
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
	//OWNER
	//CREATE
	r.Post("/register_owner", RegisterOwnerHandler(db))
	r.Get("/register_owner", RegisterOwnerHTMLHandler)
	r.Get("/login/owner", OwnerLoginHTMLHandler)
	r.Post("/login/owner", OwnerLoginHandler(db, apiCfg))
	//UPDATE
	r.With(JWTMiddleware(apiCfg, true)).Post("/owner/profile/change_password", ChangeOwnerPasswordHandler(db, apiCfg))
	r.With(JWTMiddleware(apiCfg, true)).Get("/owner/profile", OwnerProfileHTMLHandler) 
	//DELETE
	r.With(JWTMiddleware(apiCfg, true)).Post("/owner/profile/delete_account",DeleteOwnerHandler(db, apiCfg))

	//PLAYGROUND
	//CREATE
	r.With(JWTMiddleware(apiCfg, true)).Post("/register/playground", RegisterPlaygroundHandler(db, apiCfg))
	r.Get("/register/playground", ResPlayHTMLHandler)
	//READ
	r.Get("/", GetPlaygroundsHandler(db))
	r.Get("/playgrounds/{id}", GetPlaygroundHandler(db))
	//DELETE
	r.With(JWTMiddleware(apiCfg, true)).Post("/playgrounds/{id}", DeletePlaygroundHandler(db, apiCfg))

	//USER
	//CREATE
	r.Post("/register_user", RegisterUserHandler(db))
	r.Get("/register_user", RegisterUserHTMLHandler)
	r.Get("/login/user", LoginUserHTMLHandler)
	r.Post("/login/user", UserLoginHandler(db, apiCfg))
	//UPDATE
	r.With(JWTMiddleware(apiCfg, false)).Post("/user/profile/change_password", ChangePasswordHandler(db, apiCfg))
	r.With(JWTMiddleware(apiCfg, false)).Get("/user/profile", UserProfileHTMLHandler)  
	//r.Put("/users",UpdateUserHandler(db,apiCfg))
	//DELETE 
	r.With(JWTMiddleware(apiCfg, false)).Post("/user/profile/delete_account",DeleteUserHandler(db, apiCfg))


	//BOOKING
	//CREATE
	r.With(JWTMiddleware(apiCfg, false)).Post("/booking", BookPlaygroundHandler(db, apiCfg))
	r.Get("/booking", BookingHTMLHandler)
	//READ
	r.Get("/booking/{playgroundid}", GetBookingsForPlaygroundHandler(db))
	//DELETE 
	r.With(JWTMiddleware(apiCfg, false)).Post("/booking/delete",DeleteBookingHandler(db,apiCfg))

	//LOGIN PAGE
	r.Get("/login", LoginHTMLHandler)
	//SUCCESS PAGE
	r.Get("/success", SuccessHTMLHandler)
	
	//FORGOT PASSWORD
	r.Post("/password_reset_request", PasswordResetRequestHandler(db, apiCfg))
    r.Post("/reset_password", PasswordResetHandler(db, apiCfg))
	r.Get("/reset_password", ResetPasswordHTMLHandler)
	r.Get("/password_reset_request", PasswordResetRequesHTMLtHandler)

	//FILESERVER
	fileServer := http.FileServer(http.Dir("./static/"))
	protectedFileServer := http.StripPrefix("/static", fileServer)
	r.Handle("/static/*", protectedFileServer)

	go func() {
		for {
			time.Sleep(15 * time.Minute)
			loginAttemptMutex.Lock()
			loginAttempts = make(map[string]int)
			loginAttemptMutex.Unlock()
		}
	}()
	log.Println("Server started on port 8080")
	http.ListenAndServe(":8080", r)
}

// SanitizeInput sanitizes user input to prevent XSS attacks.
func SanitizeInput(input string) string {
    return template.HTMLEscapeString(input)
}
func JWTMiddleware(cfg apiConfig, isOwner bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			var claims jwt.Claims
			if isOwner {
				claims = &OwnerJWTClaims{}
			} else {
				claims = &JWTClaims{}
			}

			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte(cfg.jwtSecret), nil
			})
			if err != nil || !token.Valid {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Attach claims to the request context
			ctx := context.WithValue(r.Context(), "user", claims)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// PasswordResetRequestHandler handles password reset requests
func PasswordResetRequestHandler(db *booking.DB, apiCfg apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		email := SanitizeInput(r.FormValue("email"))
		user, err := db.GetUserByEmail(email)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// Generate password reset token
		token, err := generateResetToken(apiCfg.jwtSecret, user.ID)
		if err != nil {
			http.Error(w, "Failed to generate reset token", http.StatusInternalServerError)
			return
		}

		// Send reset email (this is a placeholder function)
		err = sendResetEmail(email, token)
		if err != nil {
			http.Error(w, "Failed to send reset email", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/success?messageType=resetRequest", http.StatusSeeOther)
	}
}

// generateResetToken generates a JWT token for password reset

func generateResetToken(secret string, userID int) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
		"purpose": "password_reset", // Token purpose
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// sendResetEmail sends a password reset email 
func sendResetEmail(email, token string) error {
	from := os.Getenv("EMAIL")
	password := os.Getenv("EMAIL_PASSWORD")

	to := []string{email}
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	message := []byte("Subject: Password Reset Request\r\n" +
		"MIME-version: 1.0;\r\n" +
		"Content-Type: text/plain; charset=\"UTF-8\";\r\n" +
		"\r\n" +
		fmt.Sprintf("To reset your password, please click the following link: http://localhost:8080/reset_password?token=%s", token))
	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func PasswordResetHandler(db *booking.DB, apiCfg apiConfig) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Parse the query parameters to get the token
        resetToken := r.FormValue("token")
        if resetToken == "" {
            http.Error(w, "Token parameter is missing", http.StatusBadRequest)
            return
        }

        // Get the new password from the form
        newPassword := r.FormValue("newPassword")
        if newPassword == "" {
            http.Error(w, "New password is missing", http.StatusBadRequest)
            return
        }

        // Verify the reset token
        claims := jwt.MapClaims{}
        token, err := jwt.ParseWithClaims(resetToken, claims, func(token *jwt.Token) (interface{}, error) {
            return []byte(apiCfg.jwtSecret), nil
        })
        if err != nil || !token.Valid {
            http.Error(w, "Invalid or expired reset token", http.StatusUnauthorized)
            return
        }

        // Ensure the token is for password reset
        if claims["purpose"] != "password_reset" {
            http.Error(w, "Invalid reset token purpose", http.StatusUnauthorized)
            return
        }

        userID, ok := claims["user_id"].(float64)
        if !ok {
            http.Error(w, "Invalid reset token claims", http.StatusUnauthorized)
            return
        }

        // Update the user's password
        _, err = db.UpdateUserPassword(int(userID), newPassword)
        if err != nil {
            http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/success?messageType=passwordResetSuccess", http.StatusSeeOther)
    }
}


func ChangePasswordHandler(db *booking.DB, apiCfg apiConfig) http.HandlerFunc {
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
			return []byte(apiCfg.jwtSecret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract user ID from the token claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		userIDFloat64, ok := claims["user_id"].(float64)
		if !ok {
			http.Error(w, "Invalid owner ID in token claims", http.StatusUnauthorized)
			return
		}

		userID := int(userIDFloat64)

        user, err := db.GetUserById(int(userID))
		if err != nil {
            http.Error(w, "User not found", http.StatusNotFound)
            return
        }
        // Parse form data
        if err := r.ParseForm(); err != nil {
            http.Error(w, "Invalid form data", http.StatusBadRequest)
            return
        }

        currentPassword := r.FormValue("current_password")
        newPassword := r.FormValue("new_password")
        if currentPassword == "" || newPassword == "" {
            http.Error(w, "Both current and new passwords are required", http.StatusBadRequest)
            return
        }

        // Verify the old password
        err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword))
        if err != nil {
            http.Error(w, "Old password is incorrect", http.StatusUnauthorized)
            return
			
        }

        // Check password complexity (if you want to enforce it on updates)
        if err := checkPasswordComplexity(newPassword); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        // Update the user's password
        _, err = db.UpdateUserPassword(int(userID), newPassword)
        if err != nil {
            http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/success?messageType=passwordChangeSuccess", http.StatusSeeOther)
    }
}
// ChangeOwnerPasswordHandler handles password changes for owners
func ChangeOwnerPasswordHandler(db *booking.DB, apiCfg apiConfig) http.HandlerFunc {
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
			return []byte(apiCfg.jwtSecret), nil
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

		owner, err := db.GetOwnerByID(ownerID)
		if err != nil {
			http.Error(w, "Owner not found", http.StatusNotFound)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		if currentPassword == "" || newPassword == "" {
			http.Error(w, "Both current and new passwords are required", http.StatusBadRequest)
			return
		}

		// Verify the old password
		err = bcrypt.CompareHashAndPassword([]byte(owner.Password), []byte(currentPassword))
		if err != nil {
			http.Error(w, "Old password is incorrect", http.StatusUnauthorized)
			return
		}

		// Check password complexity (if you want to enforce it on updates)
		if err := checkPasswordComplexity(newPassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Update the owner's password
		_, err = db.UpdateOwnerPassword(ownerID, newPassword)
		if err != nil {
			http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/success?messageType=passwordChangeSuccess", http.StatusSeeOther)
	}
}

// Define a function to render the page with header and footer templates
func renderPage(w http.ResponseWriter, r *http.Request, content string) {
	headerTemplate, err := os.ReadFile("header.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Failed to read header HTML file:", err)
		return
	}

	footerTemplate, err := os.ReadFile("footer.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Failed to read footer HTML file:", err)
		return
	}

	contentTemplate, err := os.ReadFile(content)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Failed to read footer HTML file:", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")

	// Write header template
	if _, err := w.Write(headerTemplate); err != nil {
		log.Println("Failed to write header template:", err)
		return
	}

	// Write content
	if _, err := w.Write(contentTemplate); err != nil {
		log.Println("Failed to write content:", err)
		return
	}

	// Write footer template
	if _, err := w.Write(footerTemplate); err != nil {
		log.Println("Failed to write footer template:", err)
		return
	}
}

func BookingHTMLHandler(w http.ResponseWriter, r *http.Request) {
	// Read the HTML file
	renderPage(w, r, "booking.html")

}
func UserProfileHTMLHandler(w http.ResponseWriter, r *http.Request) {
    // Serve the HTML form for changing the password
    renderPage(w, r, "profile_user.html")
}
func OwnerProfileHTMLHandler(w http.ResponseWriter, r *http.Request) {
    // Serve the HTML form for changing the password
    renderPage(w, r, "profile_owner.html")
}
func PasswordResetRequesHTMLtHandler(w http.ResponseWriter, r *http.Request) {
    // Serve the HTML form for changing the password
    renderPage(w, r, "passwordreset_request.html")
}
func ResetPasswordHTMLHandler(w http.ResponseWriter, r *http.Request) {
        // Extract the token from the URL query parameters
		token := r.URL.Query().Get("token")

		// Pass the token to the HTML template
		data := struct {
			Token string
		}{
			Token: token,
		}

		    // Render the HTML template with the token value
			tmpl, err := template.ParseFiles("password_reset.html")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			err = tmpl.Execute(w ,data)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
}

func SuccessHTMLHandler(w http.ResponseWriter, r *http.Request) {
    messageType := r.URL.Query().Get("messageType")
    continueURL := "/" // Default redirect URL (adjust as needed)

    // Data to be passed to the template
    data := struct {
        Message     string
        ContinueURL string
    }{}

    switch messageType {
    case "userRegister":
        data.Message = "Congratulations, your account has been successfully created."
        data.ContinueURL = "/" 
    case "playgroundRegister":
        data.Message = "Your playground has been successfully registered."
        data.ContinueURL = "/" 
    case "bookingSuccess":
        data.Message = "Your booking was successful!"
        data.ContinueURL = "/" 
	case "loginSuccess":
        data.Message = "Your login was successful!"
        data.ContinueURL = "/" 
	case "passwordResetSuccess" :
		data.Message = "Your password has been successfully reset."
		data.ContinueURL = "/" 

    default:
        data.Message = "Success!"
		data.ContinueURL = continueURL
    }

    // Parse and execute the success.html template
    tmpl, err := template.ParseFiles("success.html")
    if err != nil {
        http.Error(w, "Failed to parse HTML template: "+err.Error(), http.StatusInternalServerError)
        return
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        http.Error(w, "Failed to execute HTML template: "+err.Error(), http.StatusInternalServerError)
        return
    }
}

func OwnerLoginHTMLHandler(w http.ResponseWriter, r *http.Request) {
	// Read the HTML file
	renderPage(w, r, "login_owner.html")
}

// Update your handlers to use the renderPage function
func MainHTMLHandler(db *booking.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		playgrounds, err := db.GetAllPlaygrounds()
		if err != nil {
			http.Error(w, "Failed to get playgrounds: "+err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl, err := template.ParseFiles("main.html")
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
func ResPlayHTMLHandler(w http.ResponseWriter, r *http.Request) {
	// Read the HTML file
	renderPage(w, r, "res_playground.html")

}
func LoginUserHTMLHandler(w http.ResponseWriter, r *http.Request) {
	// Read the HTML file
	renderPage(w, r, "login_user.html")

}

func LoginHTMLHandler(w http.ResponseWriter, r *http.Request) {

	renderPage(w, r, "login.html")

}
func checkPasswordComplexity(password string) error {
	if len(password) < 8 {
		return errors.New("password need at least 8 characters")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return errors.New("password need at least 1 upper , 1 lower ,1 digit and 1 special character")
	}

	return nil
}
type OwnerRegistration struct {
    Name     string `validate:"required,min=2,max=20"`
    Email    string `validate:"required,email"`
    Password string `validate:"required,min=8,max=20"`
    Phone    string `validate:"required"`
    Location string `validate:"required"`
}
var validate *validator.Validate

func init() {
    validate = validator.New()
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
		name := SanitizeInput(r.FormValue("name"))
		email := SanitizeInput(r.FormValue("email"))
		password := r.FormValue("password")
		phone := SanitizeInput(r.FormValue("phone"))
		location := SanitizeInput(r.FormValue("location"))

        // Extract owner data from the form
        owner := OwnerRegistration{
            Name:     name,
            Email:    email,
            Password: password,
            Phone:    phone,
            Location: location,
        }
		       // Validate the owner data
			   err = validate.Struct(owner)
			   if err != nil {
				   http.Error(w, "Invalid input: "+err.Error(), http.StatusBadRequest)
				   log.Println("Invalid input:", err)
				   return
			   }

		// Kiểm tra độ phức tạp mật khẩu
		if err := checkPasswordComplexity(password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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
		http.Redirect(w, r, "/success?messageType=userRegister", http.StatusSeeOther)
	}
}

func RegisterUserHTMLHandler(w http.ResponseWriter, r *http.Request) {
	// Read the HTML file
	renderPage(w, r, "register_user.html")

}
func RegisterOwnerHTMLHandler(w http.ResponseWriter, r *http.Request) {
	// Read the HTML file

	renderPage(w, r, "register_owner.html")

}

type UserRegistration struct {
    Email    string `validate:"required,email"`
    Password string `validate:"required,min=8,max=20"`
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
		email := SanitizeInput(r.FormValue("email"))
		password := r.FormValue("password")

		        // Extract user data from the form
				user := UserRegistration{
					Email:    email,
					Password: password,
				}

        // Validate the user data
        err = validate.Struct(user)
        if err != nil {
            http.Error(w, "Invalid input: "+err.Error(), http.StatusBadRequest)
            log.Println("Invalid input:", err)
            return
        }

		// Kiểm tra độ phức tạp mật khẩu
		if err := checkPasswordComplexity(password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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

		http.Redirect(w, r, "/success?messageType=userRegister", http.StatusSeeOther)

	}
}

// DeleteUserHandler handles deleting a user account
func DeleteUserHandler(db *booking.DB , apiCfg apiConfig ) http.HandlerFunc {
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
			return []byte(apiCfg.jwtSecret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract user ID from the token claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		userIDFloat64, ok := claims["user_id"].(float64)
		if !ok {
			http.Error(w, "Invalid user ID in token claims", http.StatusUnauthorized)
			return
		}

		userID := int(userIDFloat64)

		err = db.DeleteUser(userID)
		if err != nil {
			http.Error(w, "Failed to delete user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/success?messageType=accountDeleteSuccess", http.StatusSeeOther)
	}
}

// DeleteOwnerHandler handles deleting an owner account
func DeleteOwnerHandler(db *booking.DB, apiCfg apiConfig) http.HandlerFunc {
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
			return []byte(apiCfg.jwtSecret), nil
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

		err = db.DeleteOwner(ownerID)
		if err != nil {
			http.Error(w, "Failed to delete owner: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/success?messageType=accountDeleteSuccess", http.StatusSeeOther)
	}
}
type PlaygroundRegistration struct {
    Name               string  `validate:"required"`
    Location           string  `validate:"required"`
    Size               string  `validate:"required"`
    AvailableHours     string  `validate:"required"`
    CancellationPeriod int     `validate:"required"`
    PricePerHour       float64 `validate:"required,gt=0"`
}
func generateFilename() (string, error) {
    randomBytes := make([]byte, 16)
    _, err := rand.Read(randomBytes)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(randomBytes), nil
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
        err = r.ParseMultipartForm(32 << 20) // 32MB max file size
        if err != nil {
            http.Error(w, "Invalid form data", http.StatusBadRequest)
            return
        }

        // Get the image file from the form data
        file, header, err := r.FormFile("image")
        if err != nil {
            http.Error(w, "No image file provided", http.StatusBadRequest)
            return
        }
        defer file.Close()

        // Validate the file type and size
        contentType := header.Header.Get("Content-Type")
        if contentType != "image/jpeg" && contentType != "image/png" && contentType != "image/jpg"{
            http.Error(w, "Invalid file type", http.StatusBadRequest)
            return
        }

        if header.Size > 1024*1024*5 { // 5MB max file size
            http.Error(w, "File too large", http.StatusBadRequest)
            return
        }

        // Sanitize the filename
        allowedChars := regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
        filename := filepath.Base(header.Filename)
        if !allowedChars.MatchString(filename) {
            http.Error(w, "Invalid filename", http.StatusBadRequest)
            return
        }

        // Generate a new filename
        newFilename, err := generateFilename()
        if err != nil {
            http.Error(w, "Failed to generate filename", http.StatusInternalServerError)
            return
        }
        newFilename = newFilename + filepath.Ext(filename)

        // Read the file contents into a byte slice
        fileBytes, err := ioutil.ReadAll(file)
        if err != nil {
            http.Error(w, "Failed to read file", http.StatusInternalServerError)
            return
        }

        // Store the image securely
        imagePath := filepath.Join("static", newFilename)
        imagePath = filepath.Clean(imagePath)

        // Check if the resulting path is within the "uploads" directory
        uploadsDir, err := filepath.Abs("static")
        if err != nil {
            http.Error(w, "Server error", http.StatusInternalServerError)
            return
        }

        imagePathAbs, err := filepath.Abs(imagePath)
        if err != nil || !strings.HasPrefix(imagePathAbs, uploadsDir) {
            http.Error(w, "Invalid file path", http.StatusBadRequest)
            return
        }

        err = os.WriteFile(imagePath, fileBytes, 0644)
        if err != nil {
            http.Error(w, "Failed to save image to server", http.StatusInternalServerError)
            return
        }

		// Extract playground data from the form
		name := SanitizeInput(r.FormValue("name"))
		location := SanitizeInput(r.FormValue("location"))
		size := SanitizeInput(r.FormValue("size"))
		startTime := SanitizeInput(r.FormValue("start_time"))
		endTime := SanitizeInput(r.FormValue("end_time"))
		
		// Construct the availableHours string
		availableHours := fmt.Sprintf("%s - %s", startTime, endTime)		
		cancellation_period := SanitizeInput(r.FormValue("cancellation_period"))
		price_per_hour := SanitizeInput(r.FormValue("price_per_hour"))
		price_per_hour_float, _ := strconv.ParseFloat(strings.TrimSpace(price_per_hour), 64)
		cancellation_period_int, _ := strconv.Atoi(cancellation_period)

        // Extract playground data from the form
        playground := booking.Playground{
            Name:           name,
            Location:       location,
            Size:           size,
            AvailableHours: availableHours,
			Image: imagePath,

        }

        // Parse cancellation period with error handling
        cancellationPeriodStr := SanitizeInput(r.FormValue("cancellation_period"))
        if cancellationPeriodStr != "" { // Check if the field is empty
            var err error
            playground.CancellationPeriod, err = strconv.Atoi(cancellationPeriodStr)
            if err != nil {
                http.Error(w, "Invalid cancellation period", http.StatusBadRequest)
                return
            }
        }

        // Parse price per hour with error handling
        pricePerHourStr := SanitizeInput(r.FormValue("price_per_hour"))
        if pricePerHourStr != "" {  // Check if the field is empty
            var err error
            playground.PricePerHour, err = strconv.ParseFloat(pricePerHourStr, 64)
            if err != nil {
                http.Error(w, "Invalid price per hour", http.StatusBadRequest)
                return
            }
        }
	
			// Validate the playground data
			err = validate.Struct(playground)
			if err != nil {
				http.Error(w, "Invalid input: "+err.Error(), http.StatusBadRequest)
				log.Println("Invalid input:", err)
				return
			}
		// Create the playground
		_, err = db.CreatePlayground(ownerID, booking.Playground{
			Name:               name,
			Location:           location,
			Size:               size,
			AvailableHours:     availableHours,
			CancellationPeriod: cancellation_period_int,
			PricePerHour:       price_per_hour_float,
			OwnerID:            ownerID,
			Image: imagePath,

		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/success?messageType=playgroundRegister", http.StatusSeeOther)
		
	}
}

func GetPlaygroundsHandler(db *booking.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        playgrounds, err := db.GetAllPlaygrounds()
        if err != nil {
            http.Error(w, "Failed to get playgrounds: "+err.Error(), http.StatusInternalServerError)
            return
        }

        // Parse the HTML template
        tmpl, err := template.ParseFiles("playgrounds.html")
        if err != nil {
            http.Error(w, "Failed to parse HTML template: "+err.Error(), http.StatusInternalServerError)
            return
        }

        // Define a custom template function for HTML escaping
        funcMap := template.FuncMap{
            "safeHTML": func(s string) template.HTML {
                return template.HTML(html.EscapeString(s))
            },
        }

        // Associate the custom function map with the template
        tmpl = tmpl.Funcs(funcMap)

        // Execute the HTML template with the playgrounds data
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

var loginAttempts = make(map[string]int)
var loginAttemptMutex sync.Mutex

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

		// Rate limiting
		loginAttemptMutex.Lock()
		loginAttempts[email]++
		attempts := loginAttempts[email]
		loginAttemptMutex.Unlock()

		if attempts > 5 {
			http.Error(w, "Quá nhiều lần đăng nhập thất bại. Vui lòng thử lại sau 15 phút.", http.StatusTooManyRequests)
			return
		}

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

		// Calculate token expiration time (15 minutes)
		expiresAt := time.Now().UTC().Add(15 * time.Minute)

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
			Expires: expiresAt, Path: "/", MaxAge: 86400, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		})

		// If login is successful, reset the attempt counter
		loginAttemptMutex.Lock()
		delete(loginAttempts, email)
		loginAttemptMutex.Unlock()

		http.Redirect(w, r, "/success?messageType=loginSuccess", http.StatusSeeOther)

	}
}

func OwnerLoginHandler(db *booking.DB, cfg apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			log.Println("Failed to parse form data:", err)
			return
		}

		// Extract login information from the form
		email := r.FormValue("email")
		password := r.FormValue("password")

		// --- START OF RATE LIMITING ---
		loginAttemptMutex.Lock()
		loginAttempts[email]++
		attempts := loginAttempts[email]
		loginAttemptMutex.Unlock()

		if attempts > 5 {
			http.Error(w, "Quá nhiều lần đăng nhập thất bại. Vui lòng thử lại sau 15 phút.", http.StatusTooManyRequests)
			return
		}
		// --- END OF RATE LIMITING ---

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

		// Calculate token expiration time (15 minutes)
		expiresAt := time.Now().UTC().Add(15 * time.Minute)

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
			Path:    "/", MaxAge: 86400, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		})

		http.Redirect(w, r, "/success?messageType=loginSuccess", http.StatusSeeOther)
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
		// Check password complexity (if you want to enforce it on updates)
		if err := checkPasswordComplexity(updateParams.Password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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

type BookingRequest struct {
    PlaygroundID int    `validate:"required,gt=0"`
    StartTime    string `validate:"required"`
    Duration     int    `validate:"required,gt=0"`
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

		playgroundIDStr := SanitizeInput(r.Form.Get("playground_id"))
		playgroundID, err := strconv.Atoi(playgroundIDStr)
		if err != nil {
			http.Error(w, "Invalid playground ID", http.StatusBadRequest)
			return
		}

		startTimeString := SanitizeInput(r.Form.Get("start_time"))
		startTime, err := time.Parse("2006-01-02T15:04", startTimeString)
		if err != nil {
			http.Error(w, "Invalid start time", http.StatusBadRequest)
			return
		}
		durationStr := SanitizeInput(r.Form.Get("duration"))
		duration, err := strconv.Atoi(durationStr)
		if err != nil {
			http.Error(w, "Invalid duration", http.StatusBadRequest)
			return
		}
		
		        // Extract booking data from the form
				bookingRequest := BookingRequest{
					PlaygroundID: playgroundID,
					StartTime:    r.Form.Get("start_time"),
					Duration:     duration,
				}
		
				// Validate the booking request
				err = validate.Struct(bookingRequest)
				if err != nil {
					http.Error(w, "Invalid input: "+err.Error(), http.StatusBadRequest)
					log.Println("Invalid input:", err)
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

		http.Redirect(w, r, "/success?messageType=bookingSuccess", http.StatusSeeOther)
	}
}

func GetBookingsForPlaygroundHandler(db *booking.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the playground ID from the URL parameters
		playgroundIDStr := chi.URLParam(r, "playgroundid")
		playgroundID, err := strconv.Atoi(playgroundIDStr)
		if err != nil {
			http.Error(w, "Invalid playground ID", http.StatusBadRequest)
			log.Println("Invalid playground ID:", err)
			return
		}

		// Retrieve all bookings for the specified playground
		bookings, err := db.GetBookingsForPlayground(playgroundID)
		if err != nil {
			http.Error(w, "Failed to get bookings for playground: "+err.Error(), http.StatusInternalServerError)
			log.Println("Failed to get bookings for playground:", err)
			return
		}

		tmpl, err := template.ParseFiles("booking_play.html")
		if err != nil {
			http.Error(w, "Failed to parse HTML template: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, bookings)
		if err != nil {
			http.Error(w, "Failed to execute HTML template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func DeleteBookingHandler(db *booking.DB, apiCfg apiConfig) http.HandlerFunc {
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
            return []byte(apiCfg.jwtSecret), nil
        })
        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // Extract user ID from the token claims
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            http.Error(w, "Invalid token claims", http.StatusUnauthorized)
            return
        }

        userIDFloat64, ok := claims["user_id"].(float64)
        if !ok {
            http.Error(w, "Invalid user ID in token claims", http.StatusUnauthorized)
            return
        }

        userID := int(userIDFloat64)

        // Parse form data
        if err := r.ParseForm(); err != nil {
            http.Error(w, "Invalid form data", http.StatusBadRequest)
            return
        }

        bookingID := r.FormValue("booking_id")
        if bookingID == "" {
            http.Error(w, "Booking ID is required", http.StatusBadRequest)
            return
        }

        // Parse the booking ID as an integer
        bookingIDint, err := strconv.Atoi(bookingID)
        if err != nil {
            http.Error(w, "Invalid booking ID", http.StatusBadRequest)
            return
        }
        // Fetch the booking from the database
        booking, err := db.GetBookingByID(bookingIDint)
        if err != nil {
            http.Error(w, "Failed to fetch booking: "+err.Error(), http.StatusInternalServerError)
            return
        }

        // Check if the booking belongs to the user
        if booking.UserID != userID {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Delete the booking
        err = db.DeleteBooking(bookingIDint)
        if err != nil {
            http.Error(w, "Failed to delete booking: "+err.Error(), http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/success?messageType=bookingDeletionSuccess", http.StatusSeeOther)
    }
}

