package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"
)

const (
	ClientId  = "cli-auth"
	Issuer    = "http://localhost:8080/realms/master"
	TokenFile = "token"
)

func main() {
	run(os.Args[1:])
}

func run(args []string) {
	cmd := args[0]
	switch cmd {
	case "auth":
		authenticate()
		break
	case "get-user":
		getUser()
		break
	default:
		fmt.Fprintf(os.Stderr, "invalid command: %s\n", cmd)
		os.Exit(1)
	}
	os.Exit(0)
}

func authenticate() {
	port := getRandomPort()

	verifier, err := generateVerifier()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	challenge := generateS256Challenge(verifier)

	authUrl, err := getAuthUrl(port, challenge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startHttpServer(ctx, &wg, port, verifier)

	err = openUrl(authUrl)
	if err != nil {
		cancel()
		//let's give server some time to shut down gracefully
		time.Sleep(2 * time.Second)
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Finish the authentication process in the browser\n")
	wg.Wait()
	os.Exit(0)
}

func startHttpServer(ctx context.Context, wg *sync.WaitGroup, port string, verifier string) {
	ctx, cancel := context.WithCancel(ctx)
	mux := http.NewServeMux()
	mux.Handle("/", callbackHandler(cancel, port, verifier))
	server := &http.Server{
		Addr:    net.JoinHostPort("localhost", port),
		Handler: mux,
	}
	//Start the server
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
		}
	}()
	wg.Add(1)
	//Handle graceful shutdown
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 1)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "failed to shutdown server: %v\n", err)
		}
	}()
}

func callbackHandler(stopServer context.CancelFunc, port string, verifier string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer stopServer()
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "code not found", http.StatusUnauthorized)
			return
		}
		token, err := exchangeCodeForToken(code, port, verifier)
		if err != nil {
			http.Error(w, "failed to exchange code for token", http.StatusUnauthorized)
			return
		}
		err = writeTokenToFile(token)
		if err != nil {
			http.Error(w, "failed to write token to file", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Authentication successful. You can now close this tab."))
		fmt.Printf("Authentication successful\n")
	})
}

func writeTokenToFile(token string) error {
	tokenFile, err := os.Create(TokenFile)
	if err != nil {
		return fmt.Errorf("failed to create token file: %v", err)
	}
	defer tokenFile.Close()

	if _, err := tokenFile.WriteString(token); err != nil {
		return fmt.Errorf("failed to write token to file: %v", err)
	}
	return nil
}

func exchangeCodeForToken(code string, port string, verifier string) (string, error) {
	q := &url.Values{}
	q.Add("client_id", ClientId)
	q.Add("grant_type", "authorization_code")
	q.Add("code", code)
	q.Add("redirect_uri", fmt.Sprintf("http://localhost:%s", port))
	q.Add("code_verifier", verifier)

	res, err := http.PostForm(fmt.Sprintf("%s/protocol/openid-connect/token", Issuer), *q)
	if err != nil {
		return "", fmt.Errorf("failed to exchange code for token: %v", err)
	}
	defer res.Body.Close()

	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to exchange code for token: [%v] %s", res.StatusCode, string(bytes))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IdToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.Unmarshal(bytes, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	return tokenResp.AccessToken, nil
}

// Complies with IANA port range for dynamic or private ports
// https://www.rfc-editor.org/rfc/rfc6335.html#section-8.1.2
func getRandomPort() string {
	pMin := 49152
	pMax := 65535
	p := mathrand.Intn(pMax-pMin) + pMin
	for {
		//check if the port is available
		l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", p))
		if err == nil {
			l.Close()
			break
		}
		p = mathrand.Intn(pMax-pMin) + pMin
	}
	return strconv.Itoa(p)
}

// Requirements for PKCE verifier stated in RFC 7636
// https://tools.ietf.org/html/rfc7636#section-4.1
func generateVerifier() (string, error) {
	bytes := make([]byte, 40)
	_, err := cryptorand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(bytes)
	return verifier, nil
}

// Requirements for PKCE challenge stated in RFC 7636
// https://tools.ietf.org/html/rfc7636#section-4.2
func generateS256Challenge(verifier string) string {
	hash := sha256.New()
	hash.Write([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	return challenge
}

func openUrl(u *url.URL) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String()).Start()
	case "darwin":
		return exec.Command("open", u.String()).Start()
	case "linux":
		return exec.Command("xdg-open", u.String()).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func getAuthUrl(port string, challenge string) (*url.URL, error) {
	u, err := url.Parse(fmt.Sprintf("%s/protocol/openid-connect/auth", Issuer))
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %v", err)
	}

	q := &url.Values{}
	q.Add("client_id", ClientId)
	q.Add("response_type", "code")
	q.Add("scope", "openid")
	q.Add("redirect_uri", fmt.Sprintf("http://localhost:%s", port))
	q.Add("code_challenge", challenge)
	q.Add("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	return u, nil
}

func getUser() {
	token, err := readTokenFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	userInfo, err := fetchUserInfo(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", userInfo)
	os.Exit(0)
}

func readTokenFile() (string, error) {
	tokenFile, err := os.Open(TokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to open token file: %v", err)
	}
	defer tokenFile.Close()

	bytes, err := io.ReadAll(tokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read token file: %v", err)
	}
	if len(bytes) == 0 {
		return "", fmt.Errorf("no token found")
	}
	return string(bytes), nil
}

func fetchUserInfo(token string) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/protocol/openid-connect/userinfo", Issuer), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get user info: %v", err)
	}
	defer res.Body.Close()

	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}
	content := string(bytes)

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get user info: [%v] %s", res.StatusCode, content)
	}

	return content, nil
}
