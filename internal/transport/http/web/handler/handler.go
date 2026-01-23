package handler

import "github.com/SamuelWang/goauth-server/internal/service/auth"

type WebHandler struct {
	authService *auth.AuthService
}

func New(authService *auth.AuthService) *WebHandler {
	return &WebHandler{
		authService: authService,
	}
}
