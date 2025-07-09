package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/MukeshG7172/goauth/utils"
)

var ErrAuth = fmt.Errorf("unauthorized access")

func main() {
	utils.ConnectDB()
	defer utils.DB.Close(context.Background())

	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.HandleFunc("/users", listUsers)

	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		fmt.Println("Server failed:", err)
	}
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) < 5 || len(password) < 5 {
		http.Error(w, "Invalid username/password", http.StatusNotAcceptable)
		return
	}

	var exists string
	err = utils.DB.QueryRow(context.Background(),
		`SELECT username FROM users WHERE username=$1`, username).Scan(&exists)

	if err == nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		http.Error(w, "Password hashing failed", http.StatusInternalServerError)
		return
	}

	_, err = utils.DB.Exec(context.Background(),
		`INSERT INTO users (username, hashed_password) VALUES ($1, $2)`, username, hashedPassword)
	if err != nil {
		http.Error(w, "Failed to insert user", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "User registered successfully!")
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var hashedPassword string
	err := utils.DB.QueryRow(context.Background(),
		`SELECT hashed_password FROM users WHERE username=$1`, username).Scan(&hashedPassword)

	if err != nil || !utils.CheckPassword(password, hashedPassword) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	sessionToken := utils.GenerateToken(32)
	csrfToken := utils.GenerateToken(32)

	// Set cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "session-token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf-token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
	})

	// Store in DB
	_, err = utils.DB.Exec(context.Background(),
		`UPDATE users SET session_token=$1, csrf_token=$2 WHERE username=$3`,
		sessionToken, csrfToken, username)

	if err != nil {
		http.Error(w, "Failed to store session data", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Login successful!!")
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")

	// Expire cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "session-token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf-token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	_, err := utils.DB.Exec(context.Background(),
		`UPDATE users SET session_token='', csrf_token='' WHERE username=$1`, username)
	if err != nil {
		http.Error(w, "Failed to clear session in DB", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Logged out successfully!")
}

func protected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	if err := Authorize(r); err != nil {
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}

	username := r.FormValue("username")
	fmt.Fprintf(w, "CSRF validation successful! Welcome, %s\n", username)
}

func listUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	rows, err := utils.DB.Query(context.Background(), `SELECT username FROM users ORDER BY username ASC`)
	if err != nil {
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	fmt.Fprintln(w, "Registered users:")
	found := false
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			http.Error(w, "Error reading user", http.StatusInternalServerError)
			return
		}
		found = true
		fmt.Fprintln(w, "- "+username)
	}

	if !found {
		fmt.Fprintln(w, "No registered users.")
	}
}

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	var sessionToken, csrfToken string

	err := utils.DB.QueryRow(context.Background(),
		`SELECT session_token, csrf_token FROM users WHERE username=$1`, username).
		Scan(&sessionToken, &csrfToken)
	if err != nil {
		return ErrAuth
	}

	st, err := r.Cookie("session-token")
	if err != nil || st.Value != sessionToken {
		return ErrAuth
	}

	csrf := r.Header.Get("csrf-token")
	if csrf == "" || csrf != csrfToken {
		return ErrAuth
	}

	return nil
}
