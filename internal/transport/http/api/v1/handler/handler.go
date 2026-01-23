package handler

import "github.com/SamuelWang/goauth-server/internal/service/auth"

type ApiV1Handler struct {
	authService *auth.AuthService
}

func New(authService *auth.AuthService) *ApiV1Handler {
	return &ApiV1Handler{
		authService: authService,
	}
}
