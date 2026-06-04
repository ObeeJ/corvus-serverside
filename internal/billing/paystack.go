package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// PRO_PRICE_NGN is the monthly Pro plan price in kobo (NGN * 100).
const PRO_PRICE_NGN = 1650000 // ₦16,500 in kobo

// PRO_PRICE_USDC is the monthly Pro plan price in USDC (micro-units, 6 decimals).
const PRO_PRICE_USDC = 10_000000 // $10 USDC

// Receiving addresses per network/token. Configure via environment variables in
// production; the defaults below are non-functional placeholders.
var (
	BTCAddress      = envOr("CORVUS_BTC_ADDRESS", "bc1qexampleexampleexampleexampleexampleex")
	ETHAddress      = envOr("CORVUS_ETH_ADDRESS", "0x000000000000000000000000000000000000dEaD")
	USDTEthAddress  = envOr("CORVUS_USDT_ETH_ADDRESS", "0x000000000000000000000000000000000000dEaD")
	USDTBaseAddress = envOr("CORVUS_USDT_BASE_ADDRESS", "0x000000000000000000000000000000000000dEaD")
	USDTArbAddress  = envOr("CORVUS_USDT_ARB_ADDRESS", "0x000000000000000000000000000000000000dEaD")
	USDTTronAddress = envOr("CORVUS_USDT_TRON_ADDRESS", "TExampleExampleExampleExampleExample")
	USDCSolAddress  = envOr("CORVUS_USDC_SOL_ADDRESS", "So1ExampleExampleExampleExampleExampleExample")
)

// envOr returns the environment variable value for key, or fallback when unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// CryptoOption describes a supported crypto payment method.
type CryptoOption struct {
	Token   string
	Network string
	Address string
	Amount  string
}

// SupportedCryptoOptions returns all supported payment options.
func SupportedCryptoOptions() []CryptoOption {
	return []CryptoOption{
		{Token: "BTC",  Network: "bitcoin",  Address: BTCAddress,      Amount: "0.00015"},
		{Token: "ETH",  Network: "ethereum", Address: ETHAddress,      Amount: "0.005"},
		{Token: "USDT", Network: "ethereum", Address: USDTEthAddress,  Amount: "10"},
		{Token: "USDT", Network: "base",     Address: USDTBaseAddress, Amount: "10"},
		{Token: "USDT", Network: "arbitrum", Address: USDTArbAddress,  Amount: "10"},
		{Token: "USDT", Network: "tron",     Address: USDTTronAddress, Amount: "10"},
		{Token: "USDC", Network: "solana",   Address: USDCSolAddress,  Amount: "10"},
	}
}

// GetCryptoPaymentInfo returns payment details for a given token+network.
func GetCryptoPaymentInfo(userID, reference, token, network string) (*CryptoPaymentInfo, error) {
	for _, opt := range SupportedCryptoOptions() {
		if opt.Token == token && opt.Network == network {
			return &CryptoPaymentInfo{
				Network:   opt.Network,
				Token:     opt.Token,
				Address:   opt.Address,
				Amount:    opt.Amount,
				Reference: reference,
			}, nil
		}
	}
	return nil, fmt.Errorf("unsupported token/network: %s/%s", token, network)
}

// PaystackService handles Paystack payment initialization and verification.
type PaystackService struct {
	secretKey  string
	publicKey  string
	successURL string
	cancelURL  string
	httpClient *http.Client
	log        *slog.Logger
}

func NewPaystackService(log *slog.Logger) *PaystackService {
	baseURL := os.Getenv("PUBLIC_URL")
	if baseURL == "" {
		baseURL = "http://localhost:3000"
	}
	return &PaystackService{
		secretKey:  os.Getenv("PAYSTACK_SECRET_KEY"),
		publicKey:  os.Getenv("PAYSTACK_PUBLIC_KEY"),
		successURL: baseURL + "/billing?success=true",
		cancelURL:  baseURL + "/billing?canceled=true",
		httpClient: &http.Client{Timeout: 15 * time.Second},
		log:        log,
	}
}

type paystackInitRequest struct {
	Email       string            `json:"email"`
	Amount      int               `json:"amount"` // kobo
	Reference   string            `json:"reference"`
	CallbackURL string            `json:"callback_url"`
	Metadata    map[string]string `json:"metadata"`
}

type paystackInitResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    struct {
		AuthorizationURL string `json:"authorization_url"`
		Reference        string `json:"reference"`
	} `json:"data"`
}

// InitializeTransaction creates a Paystack payment link for the Pro plan.
func (s *PaystackService) InitializeTransaction(ctx context.Context, userID, email, reference string) (string, error) {
	if s.secretKey == "" {
		return "", fmt.Errorf("PAYSTACK_SECRET_KEY not set")
	}

	body := paystackInitRequest{
		Email:       email,
		Amount:      PRO_PRICE_NGN,
		Reference:   reference,
		CallbackURL: s.successURL,
		Metadata:    map[string]string{"user_id": userID},
	}
	data, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.paystack.co/transaction/initialize", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.secretKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("paystack request: %w", err)
	}
	defer resp.Body.Close()

	var result paystackInitResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding paystack response: %w", err)
	}
	if !result.Status {
		return "", fmt.Errorf("paystack error: %s", result.Message)
	}

	return result.Data.AuthorizationURL, nil
}

// VerifyTransaction verifies a Paystack payment reference.
func (s *PaystackService) VerifyTransaction(ctx context.Context, reference string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.paystack.co/transaction/verify/"+reference, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+s.secretKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Status bool `json:"status"`
		Data   struct {
			Status string `json:"status"` // "success" | "failed" | "pending"
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.Status && result.Data.Status == "success", nil
}

// VerifyWebhookSignature validates a Paystack webhook payload.
func VerifyWebhookSignature(payload []byte, signature, secretKey string) bool {
	mac := hmac.New(sha512.New, []byte(secretKey))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// CryptoPaymentInfo holds the details needed for a crypto payment.
type CryptoPaymentInfo struct {
	Network   string `json:"network"`
	Token     string `json:"token"`
	Address   string `json:"address"`
	Amount    string `json:"amount"`
	Reference string `json:"reference"`
}
