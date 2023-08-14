package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	path string
	mux  *sync.RWMutex
    maxID int
}


type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps,omitempty"`
    Users map[int]User `json:"users,omitempty"`
}

type Chirp struct {
	Id int `json:"id,omitempty"`
	Body string `json:"body,omitempty"`
	
}
type User struct {
	Id int `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}
// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
    db := &DB{
        path: path,
        mux:  &sync.RWMutex{},
        maxID: 0,
    }
    if err := db.ensureDB(); err != nil {
        os.Create("database.json")
    }
    return db, nil
}


// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string) (Chirp, error) {
    db.mux.Lock()
    defer db.mux.Unlock()
    db.maxID++
    newchirps := Chirp{
        Id : db.maxID,
        Body: body,
    }
    dbstruct, _  := db.loadDB()
    if dbstruct.Chirps == nil {
        dbstruct.Chirps = make(map[int]Chirp)
    }
    dbstruct.Chirps[newchirps.Id] = newchirps
    db.writeDB(dbstruct)
    return newchirps, nil
}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
    db.mux.Lock()
    defer db.mux.Unlock()
    data, err := os.ReadFile("database.json")
    if err != nil {
        return nil, err
    }
    dat := bytes.NewReader(data)
    newstruct := DBStructure{}
    decoder := json.NewDecoder(dat)
    err = decoder.Decode(&newstruct)
    if err != nil { return nil, err}
    chirps := make([]Chirp, 0)
    for _, chirp := range newstruct.Chirps {
        chirps = append(chirps, chirp)
    }
    return chirps,nil
}
//Create user and store to disk
func (db *DB) CreateUser(email string, passwd string) (User, error) {
    db.mux.Lock()
    defer db.mux.Unlock()
    db.maxID++
    securepasswd,_ := bcrypt.GenerateFromPassword([]byte(passwd),bcrypt.DefaultCost)
    newusers := User{
        Id : db.maxID,
        Email: email,
        Password: string(securepasswd),
    }
    dbstruct, _  := db.loadDB()
    for _ , data := range dbstruct.Users {
        if data.Email == email {return User{},fmt.Errorf("email already exists")}
    } 
    if dbstruct.Users == nil {
        dbstruct.Users = make(map[int]User)
    }
    dbstruct.Users[newusers.Id] = newusers
    db.writeDB(dbstruct)
    return newusers, nil
}
//Get chirp by id 
func (db *DB) GetChirpsById(chirpID int) (Chirp, error) {
    db.mux.Lock()
    defer db.mux.Unlock()
    data, _ := os.ReadFile("database.json")
    dat := bytes.NewReader(data)
    newstruct := DBStructure{}
    decoder := json.NewDecoder(dat)
    decoder.Decode(&newstruct)
    chirps := Chirp{
        Id : chirpID,
        Body:  newstruct.Chirps[chirpID].Body,
    }
    return chirps,nil
}

func (db *DB) GetUserbyEmail(email string, passwd string) (User, error) {
    db.mux.Lock()
    defer db.mux.Unlock()
    data, _ := os.ReadFile("database.json")
    dat := bytes.NewReader(data)
    newstruct := DBStructure{}
    decoder := json.NewDecoder(dat)
    decoder.Decode(&newstruct)
    for _ , data := range newstruct.Users {
        if data.Email == email && bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(passwd)) == nil {
            users := User{
                Id: data.Id,
                Email: data.Email,
            }
            return users , nil
        }       
    }
    return User{},fmt.Errorf("wrong password")
}
// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
    _, err := os.ReadFile("database.json")
    if errors.Is(err, fs.ErrNotExist) ; err != nil {
        return err
    }
    return nil
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
    datadb , _ := os.ReadFile("database.json")
    data := strings.NewReader(string(datadb))
    decoder := json.NewDecoder(data)
    dbstruct := DBStructure{}
    err := decoder.Decode(&dbstruct)
    return dbstruct, err

}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
    data , err := json.Marshal(dbStructure)
    os.WriteFile("database.json",data,0666)
    return err
}