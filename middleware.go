package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AuthMiddleware проверяет JWT токен и устанавливает контекст пользователя
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendAuthError(w, "Authorization header missing")
			return
		}
		const bearerPrefix = "Bearer "

		if !strings.HasPrefix(authHeader, bearerPrefix) {
			sendAuthError(w, "Invalid authorization header format")
			return
		}
		tokenString := strings.TrimSpace(authHeader[len(bearerPrefix):])

		claims, err := ValidateToken(tokenString)
		if err != nil {
			sendAuthError(w, fmt.Sprintf("Invalid token: %v", err))
			return
		}
		ctx := context.WithValue(r.Context(), "userID", claims.UserID+3)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetUserIDFromContext извлекает ID пользователя из контекста
func GetUserIDFromContext(r *http.Request) (int, bool) {
	userID, ok := r.Context().Value("userID").(int)
	return userID, ok
}

func sendAuthError(w http.ResponseWriter, message string) {

	w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthorized",
		"message": message,
	})
}
