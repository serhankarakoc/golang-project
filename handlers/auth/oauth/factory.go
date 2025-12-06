package oauth

import (
	"os"
	"zatrano/configs/logconfig"
	"zatrano/services"
)

// ProviderFactory - OAuth provider'ları oluşturan factory
type ProviderFactory struct{}

// NewProviderFactory - Yeni provider factory oluşturur
func NewProviderFactory() *ProviderFactory {
	return &ProviderFactory{}
}

// CreateOAuthHandler - Tüm provider'ları kaydedilmiş OAuth handler oluşturur
func (f *ProviderFactory) CreateOAuthHandler(authService services.IAuthService) *OAuthHandler {
	handler := NewOAuthHandler(authService)

	// Google provider'ını kaydet
	if googleProvider := f.CreateGoogleProvider(); googleProvider != nil {
		handler.RegisterProvider(googleProvider)
	}

	// İleride diğer provider'lar buraya eklenecek
	// if facebookProvider := f.CreateFacebookProvider(); facebookProvider != nil {
	//     handler.RegisterProvider(facebookProvider)
	// }

	// if githubProvider := f.CreateGitHubProvider(); githubProvider != nil {
	//     handler.RegisterProvider(githubProvider)
	// }

	return handler
}

// CreateGoogleProvider - Google provider oluşturur
func (f *ProviderFactory) CreateGoogleProvider() *GoogleProvider {
	// Environment variable'ları kontrol et
	if os.Getenv("GOOGLE_CLIENT_ID") == "" ||
		os.Getenv("GOOGLE_CLIENT_SECRET") == "" ||
		os.Getenv("GOOGLE_REDIRECT_URI") == "" {
		logconfig.Log.Warn("Google OAuth environment variables eksik, Google OAuth devre dışı")
		return nil // Google OAuth devre dışı
	}

	return NewGoogleProvider()
}
