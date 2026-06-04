package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// ChainVerifier checks on-chain transactions using free public explorer APIs.
// No API keys required for basic verification — uses public endpoints.
type ChainVerifier struct {
	http *http.Client
}

func NewChainVerifier() *ChainVerifier {
	return &ChainVerifier{
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// VerifyResult holds the result of an on-chain verification.
type VerifyResult struct {
	Confirmed   bool
	ToAddress   string
	Amount      string // human-readable
	Token       string
	Network     string
	BlockNumber int64
	Error       string
}

// Verify checks a transaction hash on the appropriate chain.
// It returns whether the tx is confirmed and sent to our receiving address.
func (v *ChainVerifier) Verify(ctx context.Context, txHash, network, token string) (*VerifyResult, error) {
	switch network {
	case "base":
		return v.verifyEVM(ctx, txHash, network, token, "https://api.basescan.org/api", os.Getenv("BASESCAN_API_KEY"))
	case "polygon":
		return v.verifyEVM(ctx, txHash, network, token, "https://api.polygonscan.com/api", os.Getenv("POLYGONSCAN_API_KEY"))
	case "ethereum":
		return v.verifyEVM(ctx, txHash, network, token, "https://api.etherscan.io/api", os.Getenv("ETHERSCAN_API_KEY"))
	case "arbitrum":
		return v.verifyEVM(ctx, txHash, network, token, "https://api.arbiscan.io/api", os.Getenv("ARBISCAN_API_KEY"))
	case "solana":
		return v.verifySolana(ctx, txHash)
	case "bitcoin":
		return v.verifyBitcoin(ctx, txHash)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}

// verifyEVM checks EVM-compatible chains via Etherscan-compatible APIs.
// For native ETH transfers it checks the tx directly.
// For ERC-20/token transfers it checks the token transfer logs.
func (v *ChainVerifier) verifyEVM(ctx context.Context, txHash, network, token, baseURL, apiKey string) (*VerifyResult, error) {
	// Get our receiving address for this network
	opt := findCryptoOption(token, network)
	if opt == nil {
		return nil, fmt.Errorf("no receiving address configured for %s/%s", token, network)
	}
	expectedAddr := strings.ToLower(opt.Address)

	// Build URL — works without API key but rate-limited
	url := fmt.Sprintf("%s?module=proxy&action=eth_getTransactionByHash&txhash=%s", baseURL, txHash)
	if apiKey != "" {
		url += "&apikey=" + apiKey
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("explorer request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Result struct {
			To          string `json:"to"`
			Value       string `json:"value"`
			BlockNumber string `json:"blockNumber"`
			Input       string `json:"input"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode explorer response: %w", err)
	}

	tx := result.Result
	if tx.BlockNumber == "" || tx.BlockNumber == "null" {
		return &VerifyResult{Confirmed: false, Error: "transaction not yet confirmed"}, nil
	}

	toAddr := strings.ToLower(tx.To)

	// For ERC-20 tokens (USDC, USDT), the tx.To is the token contract, not our address.
	// The actual recipient is encoded in the input data.
	// We check if our address appears in the input data as a simple heuristic.
	if token == "USDC" || token == "USDT" {
		inputLower := strings.ToLower(tx.Input)
		addrWithoutPrefix := strings.TrimPrefix(expectedAddr, "0x")
		if !strings.Contains(inputLower, addrWithoutPrefix) {
			return &VerifyResult{
				Confirmed: false,
				ToAddress: toAddr,
				Error:     fmt.Sprintf("recipient address not found in token transfer data (expected %s)", expectedAddr),
			}, nil
		}
		return &VerifyResult{
			Confirmed: true,
			ToAddress: expectedAddr,
			Token:     token,
			Network:   network,
			Amount:    opt.Amount,
		}, nil
	}

	// Native ETH transfer
	if toAddr != expectedAddr {
		return &VerifyResult{
			Confirmed: false,
			ToAddress: toAddr,
			Error:     fmt.Sprintf("transaction sent to wrong address: got %s, expected %s", toAddr, expectedAddr),
		}, nil
	}

	return &VerifyResult{
		Confirmed: true,
		ToAddress: toAddr,
		Token:     token,
		Network:   network,
		Amount:    opt.Amount,
	}, nil
}

// verifySolana checks a Solana transaction using the public RPC.
func (v *ChainVerifier) verifySolana(ctx context.Context, txHash string) (*VerifyResult, error) {
	opt := findCryptoOption("SOL", "solana")
	if opt == nil {
		return nil, fmt.Errorf("no SOL receiving address configured")
	}

	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["%s",{"encoding":"json","maxSupportedTransactionVersion":0}]}`, txHash)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.mainnet-beta.solana.com",
		strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("solana RPC request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Result struct {
			Slot int64 `json:"slot"`
			Meta struct {
				Err interface{} `json:"err"`
			} `json:"meta"`
			Transaction struct {
				Message struct {
					AccountKeys []string `json:"accountKeys"`
				} `json:"message"`
			} `json:"transaction"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode solana response: %w", err)
	}

	if result.Result.Slot == 0 {
		return &VerifyResult{Confirmed: false, Error: "transaction not found or not confirmed"}, nil
	}
	if result.Result.Meta.Err != nil {
		return &VerifyResult{Confirmed: false, Error: "transaction failed on-chain"}, nil
	}

	// Check if our address is in the account keys
	for _, key := range result.Result.Transaction.Message.AccountKeys {
		if key == opt.Address {
			return &VerifyResult{
				Confirmed: true,
				ToAddress: opt.Address,
				Token:     "SOL",
				Network:   "solana",
				Amount:    opt.Amount,
			}, nil
		}
	}

	return &VerifyResult{
		Confirmed: false,
		Error:     fmt.Sprintf("our address %s not found in transaction accounts", opt.Address),
	}, nil
}

// verifyBitcoin checks a Bitcoin transaction using Blockstream's free API.
func (v *ChainVerifier) verifyBitcoin(ctx context.Context, txHash string) (*VerifyResult, error) {
	opt := findCryptoOption("BTC", "bitcoin")
	if opt == nil {
		return nil, fmt.Errorf("no BTC receiving address configured")
	}

	url := fmt.Sprintf("https://blockstream.info/api/tx/%s", txHash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("blockstream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &VerifyResult{Confirmed: false, Error: "transaction not found"}, nil
	}

	var tx struct {
		Status struct {
			Confirmed   bool  `json:"confirmed"`
			BlockHeight int64 `json:"block_height"`
		} `json:"status"`
		Vout []struct {
			ScriptpubkeyAddress string `json:"scriptpubkey_address"`
			Value               int64  `json:"value"` // satoshis
		} `json:"vout"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tx); err != nil {
		return nil, fmt.Errorf("failed to decode blockstream response: %w", err)
	}

	if !tx.Status.Confirmed {
		return &VerifyResult{Confirmed: false, Error: "transaction not yet confirmed (0 confirmations)"}, nil
	}

	for _, out := range tx.Vout {
		if out.ScriptpubkeyAddress == opt.Address {
			btcAmount := float64(out.Value) / 1e8
			return &VerifyResult{
				Confirmed:   true,
				ToAddress:   opt.Address,
				Token:       "BTC",
				Network:     "bitcoin",
				Amount:      fmt.Sprintf("%.8f", btcAmount),
				BlockNumber: tx.Status.BlockHeight,
			}, nil
		}
	}

	return &VerifyResult{
		Confirmed: false,
		Error:     fmt.Sprintf("our address %s not found in transaction outputs", opt.Address),
	}, nil
}

// findCryptoOption looks up the CryptoOption for a given token+network.
func findCryptoOption(token, network string) *CryptoOption {
	for _, opt := range SupportedCryptoOptions() {
		if opt.Token == token && opt.Network == network {
			return &opt
		}
	}
	return nil
}
