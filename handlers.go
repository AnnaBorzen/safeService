package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// RegisterHandler обрабатывает регистрацию нового пользователя
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var registerRequest RegisterRequest
	if err := parseJSONRequest(r, &registerRequest); err != nil {
		sendErrorResponse(w, "Failed to parse user info", http.StatusInternalServerError)
		log.Printf("JSON decode error: %v", err)
		return
	}

	errValidate := validateRegisterRequest(&registerRequest)
	if errValidate != nil {
		sendErrorResponse(w, errValidate.Error(), http.StatusBadRequest)
		return
	}

	existsEmail, err := UserExistsByEmail(registerRequest.Email)
	if err != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Error checking email existence: %v", err)
		return
	}
	if existsEmail {
		sendErrorResponse(w, "Email already registered", http.StatusConflict)
		return
	}

	hashPassword, errHashPassword := HashPassword(registerRequest.Password)
	if errHashPassword != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Failed to hash password: %v", err)
		return
	}

	user, err := CreateUser(registerRequest.Email, registerRequest.Username, hashPassword)
	if err != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Failed to create user: %v", err)
		return
	}

	jwtToken, errToken := GenerateToken(*user)
	if errToken != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Failed to generate token: %v", err)
		return
	}

	response := AuthResponse{
		Token: jwtToken,
		User:  *user,
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// LoginHandler обрабатывает вход пользователя
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginRequest LoginRequest
	if err := parseJSONRequest(r, &loginRequest); err != nil {
		sendErrorResponse(w, "Failed to parse user info", http.StatusInternalServerError)
		log.Printf("JSON decode error: %v", err)
		return
	}

	errValidate := validateLoginRequest(&loginRequest)
	if errValidate != nil {
		sendErrorResponse(w, errValidate.Error(), http.StatusBadRequest)
		return
	}

	user, err := GetUserByEmail(loginRequest.Email)
	if err != nil {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		log.Printf("Get user email error: %v", err)
		return
	}

	if !CheckPassword(loginRequest.Password, user.PasswordHash) {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	jwtToken, errToken := GenerateToken(*user)
	if errToken != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Failed to generate token: %v", err)
		return
	}

	response := AuthResponse{
		Token: jwtToken,
		User:  *user,
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// ProfileHandler возвращает профиль текущего пользователя
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := GetUserIDFromContext(r)
	if !ok {
		sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := GetUserByID(userID)
	if err != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Failed get user by id: %v", err)
		return
	}

	sendJSONResponse(w, user, http.StatusOK)
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

	errValidatorEmail := ValidateEmail(req.Email)
	if errValidatorEmail != nil {
		return errValidatorEmail
	}

	errValidatorPassword := ValidatePassword(req.Password)
	if errValidatorPassword != nil {
		return errValidatorPassword
	}

	errValidatorUserName := ValidateUsername(req.Username)
	if errValidatorUserName != nil {
		return errValidatorUserName
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
