package booking

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Playground struct {
	ID               int     `json:"id,omitempty"`
	Name             string  `json:"name,omitempty"`
	Location         string  `json:"location,omitempty"`
	Size             string  `json:"size,omitempty"`
	AvailableHours   string  `json:"available_hours,omitempty"`
	PricePerHour     float64 `json:"price_per_hour,omitempty"`
	CancellationPeriod int    `json:"cancellation_period,omitempty"`
	OwnerID          int     `json:"owner_id,omitempty"` 
	Image string `json:"image,omitempty"`
}

type User struct {
	ID       int    `json:"id,omitempty"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Expr     int    `json:"expires_in_seconds,omitempty"`
	Token    *string `json:"token,omitempty"`
	PreviousPasswords []string  `json:"previous_passwords"` // Array to store old passwords
    PasswordChangedAt time.Time `json:"password_changed_at"` // Add a new field

	
}

type Owner struct {
	ID             int     `json:"id,omitempty"`
	Name           string  `json:"name,omitempty"`
	Email          string  `json:"email"`
	Password       string  `json:"password"`
	Phone          string  `json:"phone,omitempty"`
	Location       string  `json:"location,omitempty"`
}

type DB struct {
    path  string
    mux   *sync.RWMutex
    maxID int
}

type DBStructure struct {
	Playgrounds map[int]Playground `json:"playgrounds,omitempty"`
	Users       map[int]User       `json:"users,omitempty"`
	Owners      map[int]Owner      `json:"owners,omitempty"`
    Bookings    map[int]Booking    `json:"bookings,omitempty"`
}

func NewDB(path string) (*DB, error) {
    db := &DB{
        path:  path,
        mux:   &sync.RWMutex{},
        maxID: 0,
    }

    if err := db.ensureDB(); err != nil {
        return nil, err

    }

    // Log a message indicating that the DB was successfully created
    log.Println("Database created successfully")

    return db, nil
}

func (db *DB) ensureDB() error {
    _, err := os.ReadFile("database.json")
    if errors.Is(err, fs.ErrNotExist); err != nil {
        return err
    }
    return nil
}

func (db *DB) loadDB() (DBStructure, error) {
    datadb, _ := os.ReadFile("database.json")
    data := strings.NewReader(string(datadb))
    decoder := json.NewDecoder(data)
    dbstruct := DBStructure{}
    err := decoder.Decode(&dbstruct)
    if err != nil {
        return DBStructure{}, err
    }
    if dbstruct.Bookings == nil {
        dbstruct.Bookings = make(map[int]Booking)
    }
    return dbstruct, nil
}


// Inside writeDB function in DB struct
func (db *DB) writeDB(dbStructure DBStructure) error {
    data, err := json.Marshal(dbStructure)
    if err != nil {
        return err
    }

    // Add log statement to check the data being written to the file
    fmt.Println("Data to be written to file:", string(data))

    err = os.WriteFile(db.path, data, 0644)
    if err != nil {
        return err
    }
    return nil
}

// CreatePlayground creates a new playground for the specified owner and saves it to disk
func (db *DB) CreatePlayground(ownerID int, playground Playground) (Playground, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	db.maxID++
	playground.ID = db.maxID
	playground.OwnerID = ownerID

	dbstruct, _ := db.loadDB()
	if dbstruct.Playgrounds == nil {
		dbstruct.Playgrounds = make(map[int]Playground)
	}
	dbstruct.Playgrounds[playground.ID] = playground

	db.writeDB(dbstruct)

	return playground, nil
}

// GetPlaygroundsByOwner returns all playgrounds owned by the specified owner
func (db *DB) GetPlaygroundsByOwner(ownerID int) ([]Playground, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbstruct, _ := db.loadDB()
	playgrounds := make([]Playground, 0)
	for _, playground := range dbstruct.Playgrounds {
		if playground.OwnerID == ownerID {
			playgrounds = append(playgrounds, playground)
		}
	}
	return playgrounds, nil
}

func (db *DB) GetAllPlaygrounds() ([]Playground, error) {
    db.mux.Lock()
    defer db.mux.Unlock()

    dbStruct, err := db.loadDB()
    if err != nil {
        return nil, err
    }

    playgrounds := make([]Playground, 0, len(dbStruct.Playgrounds))
    for _, playground := range dbStruct.Playgrounds {
        playgrounds = append(playgrounds, playground)
    }

    return playgrounds, nil
}

// GetPlaygroundByID returns the playground with the specified ID
func (db *DB) GetPlaygroundByID(id int) (Playground, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB() // Retrieve the entire database structure
	if err != nil {
		return Playground{}, err // Return any error encountered during loading
	}

	playground, ok := dbStruct.Playgrounds[id]
	if !ok {
		return Playground{}, errors.New("playground not found")
	}
	return playground, nil
}


// UpdatePlayground updates the specified playground in the database
func (db *DB) UpdatePlayground(id int, updatedPlayground Playground) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbstruct, _ := db.loadDB()
	if _, ok := dbstruct.Playgrounds[id]; !ok {
		return errors.New("playground not found")
	}
	updatedPlayground.ID = id
	dbstruct.Playgrounds[id] = updatedPlayground

	db.writeDB(dbstruct)
	return nil
}

// DeletePlayground deletes the specified playground from the database
func (db *DB) DeletePlayground(id int) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbstruct, _ := db.loadDB()
	if _, ok := dbstruct.Playgrounds[id]; !ok {
		return errors.New("playground not found")
	}
	delete(dbstruct.Playgrounds, id)

	db.writeDB(dbstruct)
	return nil
}



func (db *DB) CreateOwner(name, email, password, phone, location string) (Owner, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	db.maxID++
    securedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        log.Print("1")
		return Owner{}, err
	}
	newOwner := Owner{
		ID:             db.maxID,
		Name:           name,
		Email:          email,
		Password:       string(securedPassword),
		Phone:          phone,
		Location:       location,
	}

	dbStruct, err := db.loadDB()
	if err != nil {
		return Owner{}, err
	}

	if dbStruct.Owners == nil {
		dbStruct.Owners = make(map[int]Owner)
	}

	dbStruct.Owners[newOwner.ID] = newOwner

	err = db.writeDB(dbStruct)
	if err != nil {
		return Owner{}, err
	}

	return newOwner, nil
}

func (db *DB) CreateUser(email, password string) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	db.maxID++
	securedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}

	newUser := User{
		ID:       db.maxID,
		Email:    email,
		Password: string(securedPassword),
	}

	dbStruct, err := db.loadDB()
	if err != nil {       

		return User{}, err
	}

	if dbStruct.Users == nil {
		dbStruct.Users = make(map[int]User)
	}

	dbStruct.Users[newUser.ID] = newUser

	err = db.writeDB(dbStruct)
	if err != nil {

		return User{}, err
	}

	return newUser, nil
}

func (db *DB) GetUserByEmail(email string) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range dbStruct.Users {
		if user.Email == email {
			return user, nil
		}
	}

	return User{}, errors.New("user not found")
}

// GetUserByID returns the user with the specified ID from the database
func (db *DB) GetUserById(id int) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	user, ok := dbStruct.Users[id]
	if !ok {
		return User{}, errors.New("user not found")
	}

	return user, nil

}
func (db *DB) GetOwnerByEmail(email string) (Owner, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return Owner{}, err
	}

	for _, owner := range dbStruct.Owners {
		if owner.Email == email {
			return owner, nil
		}
	}

	return Owner{}, errors.New("owner not found")
}


// GetOwnerByID returns the owner with the specified ID from the database
func (db *DB) GetOwnerByID(id int) (Owner, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return Owner{}, err
	}

	owner, ok := dbStruct.Owners[id]
	if !ok {
		return Owner{}, errors.New("owner not found")
	}

	return owner, nil
}

func (db *DB) UpdateUser(userID int, email, password string) (User, error) {
    db.mux.Lock()
    defer db.mux.Unlock()

    dbStruct, err := db.loadDB()
    if err != nil {
        return User{}, err
    }

    user, ok := dbStruct.Users[userID]
    if !ok {
        return User{}, errors.New("user not found")
    }

    // Check if the new password matches any of the previous passwords
    for _, prevPassword := range user.PreviousPasswords {
        err := bcrypt.CompareHashAndPassword([]byte(prevPassword), []byte(password))
        if err == nil {
            return User{}, errors.New("new password cannot be the same as any of the previous passwords")
        }
    }

    // Update user's email, password, and password changed time
    user.Email = email
    securedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return User{}, err
    }
    user.Password = string(securedPassword)
    user.PasswordChangedAt = time.Now() // Record the time of password change

    // Store the old password in the previousPasswords array (limit to 5)
    user.PreviousPasswords = append([]string{user.Password}, user.PreviousPasswords...)
    if len(user.PreviousPasswords) > 5 {
        user.PreviousPasswords = user.PreviousPasswords[:5] 
    }

    // Update the user in the database structure
    dbStruct.Users[userID] = user

    // Write the updated database structure to the file
    err = db.writeDB(dbStruct)
    if err != nil {
        return User{}, err
    }

    return user, nil
}

func (db *DB) UpdateUserPassword(userID int, newPassword string) (User, error) {
    db.mux.Lock()
    defer db.mux.Unlock()

    dbStruct, err := db.loadDB()
    if err != nil {
        return User{}, err
    }

    user, ok := dbStruct.Users[userID]
    if !ok {
        return User{}, errors.New("user not found")
    }

    // Check if the new password matches any of the previous passwords
    for _, prevPassword := range user.PreviousPasswords {
        err := bcrypt.CompareHashAndPassword([]byte(prevPassword), []byte(newPassword))
        if err == nil {
            return User{}, errors.New("new password cannot be the same as any of the previous passwords")
        }
    }

    // Encrypt the new password
    securedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
    if err != nil {
        return User{}, err
    }

    // Store the old password in the previousPasswords array (limit to 5)
    user.PreviousPasswords = append([]string{user.Password}, user.PreviousPasswords...)
    if len(user.PreviousPasswords) > 5 {
        user.PreviousPasswords = user.PreviousPasswords[:5]
    }

    // Update user's password and password changed time
    user.Password = string(securedPassword)
    user.PasswordChangedAt = time.Now() // Record the time of password change

    // Update the user in the database structure
    dbStruct.Users[userID] = user

    // Write the updated database structure to the file
    err = db.writeDB(dbStruct)
    if err != nil {
        return User{}, err
    }

    return user, nil
}

func (db *DB) UpdateOwnerPassword(ownerID int, newPassword string) (Owner, error) {
    db.mux.Lock()
    defer db.mux.Unlock()

    dbStruct, err := db.loadDB()
    if err != nil {
        return Owner{}, err
    }

    owner, ok := dbStruct.Owners[ownerID]
    if !ok {
        return Owner{}, errors.New("owner not found")
    }


    // Encrypt the new password
    securedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
    if err != nil {
        return Owner{}, err
    }

    // Update owner's password and password changed time
    owner.Password = string(securedPassword)

    // Update the owner in the database structure
    dbStruct.Owners[ownerID] = owner

    // Write the updated database structure to the file
    err = db.writeDB(dbStruct)
    if err != nil {
        return Owner{}, err
    }

    return owner, nil
}

func (db *DB) DeleteOwner(id int) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbstruct, _ := db.loadDB()
	if _, ok := dbstruct.Owners[id]; !ok {
		return errors.New("owner not found")
	}
	delete(dbstruct.Owners, id)

	db.writeDB(dbstruct)
	return nil
}

func (db *DB) DeleteUser(id int) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbstruct, _ := db.loadDB()
	if _, ok := dbstruct.Users[id]; !ok {
		return errors.New("user not found")
	}
	delete(dbstruct.Users, id)

	db.writeDB(dbstruct)
	return nil
}


type Booking struct {
	ID           int       `json:"id,omitempty"`
	UserID       int       `json:"user_id,omitempty"`
	PlaygroundID int       `json:"playground_id,omitempty"`
	StartTime    time.Time `json:"start_time,omitempty"`
	EndTime      time.Time `json:"end_time,omitempty"`
}

// CreateBooking creates a new booking for the specified user and playground
func (db *DB) CreateBooking(userID, playgroundID int, startTime, endTime time.Time) (Booking, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return Booking{}, err
	}

	// Check if the requested time slot is available
	if !isTimeSlotAvailable(dbStruct, playgroundID, startTime, endTime) {
		return Booking{}, errors.New("requested time slot is not available")
	}

	// Increment the maximum booking ID
	db.maxID++

	// Create a new booking
	booking := Booking{
		ID:           db.maxID,
		UserID:       userID,
		PlaygroundID: playgroundID,
		StartTime:    startTime,
		EndTime:      endTime,
	}

	// Add the booking to the database structure
	dbStruct.Bookings[booking.ID] = booking

	// Write the updated database to the file
	if err := db.writeDB(dbStruct); err != nil {
		return Booking{}, err
	}

	return booking, nil
}

// GetBookingsForUser retrieves all bookings made by the specified user
func (db *DB) GetBookingsForUser(userID int) ([]Booking, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	bookings := make([]Booking, 0)
	for _, booking := range dbStruct.Bookings {
		if booking.UserID == userID {
			bookings = append(bookings, booking)
		}
	}

	return bookings, nil
}

// GetBookingByID retrieves the booking with the specified ID
func (db *DB) GetBookingByID(bookingID int) (Booking, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return Booking{}, err
	}

	booking, ok := dbStruct.Bookings[bookingID]
	if !ok {
		return Booking{}, errors.New("booking not found")
	}

	return booking, nil
}

func (db *DB) DeleteBooking(id int) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbstruct, _ := db.loadDB()
	if _, ok := dbstruct.Bookings[id]; !ok {
		return errors.New("booking not found")
	}
	delete(dbstruct.Bookings, id)

	db.writeDB(dbstruct)
	return nil
}

// isTimeSlotAvailable checks if the requested time slot is available for booking
func isTimeSlotAvailable(dbStruct DBStructure, playgroundID int, startTime, endTime time.Time) bool {
    bookings := dbStruct.Bookings
    if bookings == nil {
        return true // If there are no bookings for the playground, the slot is available
    }

    for _, booking := range bookings {
        if booking.PlaygroundID == playgroundID {
            // Check if the requested time slot overlaps with any existing booking
            if !(endTime.Before(booking.StartTime) || startTime.After(booking.EndTime)) {
                return false
            }
        }
    }

    return true
}


// GetBookingsForPlayground retrieves all bookings made for the specified playground
func (db *DB) GetBookingsForPlayground(playgroundID int) ([]Booking, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	bookings := make([]Booking, 0)
	for _, booking := range dbStruct.Bookings {
		if booking.PlaygroundID == playgroundID {
			bookings = append(bookings, booking)
		}
	}

	return bookings, nil
}