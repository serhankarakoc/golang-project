package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"zatrano/configs/logconfig"
	"zatrano/configs/sessionconfig"
	"zatrano/pkg/flashmessages"
	"zatrano/services"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// OAuthUserInfo - Tüm provider'lardan gelen ortak kullanıcı bilgisi
type OAuthUserInfo struct {
	ProviderID string
	Email      string
	Name       string
	AvatarURL  string
}

// OAuthProvider - Tüm OAuth provider'larının implement etmesi gereken interface
type OAuthProvider interface {
	Name() string
	DisplayName() string
	Config() *oauth2.Config
	LoginURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(token *oauth2.Token) (*OAuthUserInfo, error)
}

// OAuthHandler - Tüm OAuth işlemlerini yöneten merkezi handler
type OAuthHandler struct {
	authService services.IAuthService
	providers   map[string]OAuthProvider
}

// NewOAuthHandler - Yeni OAuth handler oluşturur
func NewOAuthHandler(authService services.IAuthService) *OAuthHandler {
	return &OAuthHandler{
		authService: authService,
		providers:   make(map[string]OAuthProvider),
	}
}

// RegisterProvider - Yeni bir OAuth provider ekler
func (h *OAuthHandler) RegisterProvider(provider OAuthProvider) {
	h.providers[provider.Name()] = provider
	logconfig.Log.Info("OAuth provider kaydedildi",
		zap.String("provider", provider.Name()),
		zap.String("display_name", provider.DisplayName()))
}

// GetProvider - İsme göre provider getirir
func (h *OAuthHandler) GetProvider(name string) (OAuthProvider, error) {
	provider, exists := h.providers[name]
	if !exists {
		return nil, fmt.Errorf("oauth provider '%s' bulunamadı", name)
	}
	return provider, nil
}

// HandleLogin - Tüm provider'lar için ortak login handler
func (h *OAuthHandler) HandleLogin(c *fiber.Ctx, providerName string) error {
	provider, err := h.GetProvider(providerName)
	if err != nil {
		logconfig.Log.Error("OAuth provider bulunamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Geçersiz OAuth provider.")
		return c.Redirect("/auth/login")
	}

	// State token oluştur
	stateToken, err := generateStateToken()
	if err != nil {
		logconfig.Log.Error("State token oluşturulamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Güvenlik token'ı oluşturulamadı.")
		return c.Redirect("/auth/login")
	}

	// Session'a kaydet
	sess, err := sessionconfig.SessionStart(c)
	if err != nil {
		logconfig.Log.Error("Session başlatılamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		return c.Redirect("/auth/login")
	}

	sess.Set("oauth_state", stateToken)
	sess.Set("oauth_provider", providerName)

	if err := sess.Save(); err != nil {
		logconfig.Log.Error("Session kaydedilemedi",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Oturum kaydedilemedi.")
		return c.Redirect("/auth/login")
	}

	// Provider'ın login URL'ine yönlendir
	loginURL := provider.LoginURL(stateToken)
	return c.Redirect(loginURL, fiber.StatusTemporaryRedirect)
}

// HandleCallback - Tüm provider'lar için ortak callback handler
func (h *OAuthHandler) HandleCallback(c *fiber.Ctx, providerName string) error {
	// Provider'ı al
	provider, err := h.GetProvider(providerName)
	if err != nil {
		logconfig.Log.Error("OAuth provider bulunamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Geçersiz OAuth provider.")
		return c.Redirect("/auth/login")
	}

	// Query parametrelerini al
	state := c.Query("state")
	code := c.Query("code")

	// Validation
	if state == "" || code == "" {
		logconfig.Log.Warn("Eksik OAuth parametreleri",
			zap.String("provider", providerName),
			zap.Bool("has_state", state != ""),
			zap.Bool("has_code", code != ""))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Geçersiz OAuth yanıtı.")
		return c.Redirect("/auth/login")
	}

	// Session kontrolü
	sess, err := sessionconfig.SessionStart(c)
	if err != nil {
		logconfig.Log.Error("Session başlatılamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		return c.Redirect("/auth/login")
	}

	// State kontrolü
	savedState := sess.Get("oauth_state")
	savedProvider := sess.Get("oauth_provider")

	if savedState != state {
		logconfig.Log.Warn("Geçersiz state token",
			zap.String("provider", providerName),
			zap.String("saved_state", fmt.Sprintf("%v", savedState)),
			zap.String("received_state", state))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Geçersiz güvenlik token'ı.")
		return c.Redirect("/auth/login")
	}

	if savedProvider != providerName {
		logconfig.Log.Warn("Yanlış OAuth provider",
			zap.String("provider", providerName),
			zap.String("saved_provider", fmt.Sprintf("%v", savedProvider)))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Yanlış OAuth provider.")
		return c.Redirect("/auth/login")
	}

	// Token exchange
	token, err := provider.ExchangeCode(c.UserContext(), code)
	if err != nil {
		logconfig.Log.Error("Token exchange başarısız",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"OAuth token alınamadı.")
		return c.Redirect("/auth/login")
	}

	// User info al
	userInfo, err := provider.GetUserInfo(token)
	if err != nil {
		logconfig.Log.Error("User info alınamadı",
			zap.String("provider", providerName),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Kullanıcı bilgileri alınamadı.")
		return c.Redirect("/auth/login")
	}

	// Kullanıcıyı bul veya oluştur
	user, err := h.authService.FindOrCreateOAuthUser(
		userInfo.ProviderID,
		userInfo.Email,
		userInfo.Name,
		providerName,
	)
	if err != nil {
		logconfig.Log.Error("Kullanıcı oluşturulamadı",
			zap.String("provider", providerName),
			zap.String("email", userInfo.Email),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Kullanıcı oluşturulamadı veya giriş yapılamadı.")
		return c.Redirect("/auth/login")
	}

	// Session temizle (state token'ı)
	sess.Delete("oauth_state")
	sess.Delete("oauth_provider")

	// User session oluştur
	sess.Set("user_id", user.ID)
	sess.Set("user_type_id", user.UserTypeID)
	sess.Set("is_active", user.IsActive)
	sess.Set("login_method", providerName)

	if err := sess.Save(); err != nil {
		logconfig.Log.Error("Session kaydedilemedi",
			zap.String("provider", providerName),
			zap.Uint("user_id", user.ID),
			zap.Error(err))
		flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey,
			"Oturum kaydedilemedi.")
		return c.Redirect("/auth/login")
	}

	// Başarılı giriş
	logconfig.Log.Info("OAuth ile giriş başarılı",
		zap.String("provider", providerName),
		zap.Uint("user_id", user.ID),
		zap.String("email", user.Email))

	flashmessages.SetFlashMessage(c, flashmessages.FlashSuccessKey,
		fmt.Sprintf("%s ile giriş başarılı.", provider.DisplayName()))

	// Yönlendirme
	return redirectAfterLogin(c, user.UserTypeID)
}

// ==================== HELPER FUNCTIONS ====================

func generateStateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func redirectAfterLogin(c *fiber.Ctx, userTypeID uint) error {
	switch userTypeID {
	case 1: // Admin
		return c.Redirect("/dashboard/home", fiber.StatusSeeOther)
	default: // Normal kullanıcı
		return c.Redirect("/panel/anasayfa", fiber.StatusSeeOther)
	}
}
