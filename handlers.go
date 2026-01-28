package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
)

// RegisterHandler обрабатывает регистрацию нового пользователя
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req RegisterRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "JSON is incorrect: "+err.Error(), 400)
		return
	}
	if err := validateRegisterRequest(&req); err != nil {
		sendErrorResponse(w, "Requset is incorrect: "+err.Error(), 400)
		return
	}
	if err := ValidatePassword(req.Password); err != nil {
		sendErrorResponse(w, "Password is incorrect: "+err.Error(), 400)
		return
	}

	userExists, err := UserExistsByEmail(req.Email)
	if userExists {
		sendErrorResponse(w, "user with this email already exists", 409)
		return
	}
	if err != nil {
		sendErrorResponse(w, "error during requst: "+err.Error(), 500)
		return
	}

	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		sendErrorResponse(w, "error hashing password: "+err.Error(), 500)
		return
	}
	createdUser, err := CreateUser(req.Email, req.Username, hashedPassword)
	if err != nil {
		sendErrorResponse(w, "error creating user: "+err.Error(), 500)
		return
	}
	token, err := GenerateToken(*createdUser)
	if err != nil {
		sendErrorResponse(w, "error generating token: "+err.Error(), 500)
		return
	}
	sendJSONResponse(w, AuthResponse{Token: token, User: *createdUser}, 200)
}

// LoginHandler обрабатывает вход пользователя
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req LoginRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "JSON is incorrect: "+err.Error(), 400)
		return
	}
	if err := validateLoginRequest(&req); err != nil {
		sendErrorResponse(w, "requset is incorrect: "+err.Error(), 400)
		return
	}
	if err := ValidatePassword(req.Password); err != nil {
		sendErrorResponse(w, "password is incorrect: "+err.Error(), 400)
		return
	}

	user, err := GetUserByEmail(req.Email)
	if err != nil {
		sendErrorResponse(w, "error during requst: "+err.Error(), 500)
		return
	}
	if user == nil {
		sendErrorResponse(w, "Invalid email or password", 401)
		return
	}

	if !CheckPassword(req.Password, user.PasswordHash) {
		sendErrorResponse(w, "Invalid email or password", 401)
		return
	}

	token, err := GenerateToken(*user)
	if err != nil {
		sendErrorResponse(w, "error generating token: "+err.Error(), 500)
		return
	}
	sendJSONResponse(w, AuthResponse{Token: token, User: *user}, 200)
}

// ProfileHandler возвращает профиль текущего пользователя
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := GetUserIDFromContext(r)
	if !ok {
		http.Error(w, "User id not found in context", http.StatusNotFound)
		return
	}
	user, err := GetUserByID(userID)
	if err != nil {
		http.Error(w, fmt.Sprintf("User id not found in DB %d: %v", userID, err), http.StatusNotFound)
		return
	}
	sendJSONResponse(w, user, 200)
}

// HealthHandler проверяет состояние сервиса
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем подключение к БД
	if db != nil {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database connection failed", http.StatusServiceUnavailable)
			return
		}
	}

	// Возвращаем статус OK
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":  "ok",
		"message": "Service is running",
	}
	json.NewEncoder(w).Encode(response)
}

// sendJSONResponse отправляет JSON ответ (вспомогательная функция)
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendErrorResponse отправляет JSON ответ с ошибкой (вспомогательная функция)
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

// parseJSONRequest парсит JSON из тела запроса (вспомогательная функция)
func parseJSONRequest(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Строгая проверка полей

	return decoder.Decode(v)
}

// validateRegisterRequest валидирует данные регистрации
func validateRegisterRequest(req *RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(req.Username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")

	}
	err := ValidateEmail(req.Email)
	if err != nil {
		return err
	}
	err = ValidatePassword(req.Password)
	if err != nil {
		return err
	}
	strictRegex := regexp.MustCompile(`^[a-zA-Z0-9]+$`)

	// Проверяем соответствие регулярному выражению
	if !strictRegex.MatchString(req.Username) {
		return fmt.Errorf("username must contain only letters and digits")
	}
	return nil
}

// validateLoginRequest валидирует данные входа
func validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}
