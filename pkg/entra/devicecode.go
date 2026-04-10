package entra

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/chromedp/chromedp"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DeviceAuth struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationUri string `json:"verification_uri"`
	ExpiredIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type AuthenticationResult struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type AuthenticationError struct {
	Type        string `json:"error"`
	Description string `json:"error_description"`
}

const (
	PENDING string = "authorization_pending"
)

// https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
func RequestDeviceAuth(tenant string, clientId string, scopes []string) (*DeviceAuth, error) {
	resp, err := http.PostForm("https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/devicecode",
		url.Values{"client_id": {clientId}, "scope": {strings.Join(scopes, " ")}})

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		errMsg := "Request failed with status code:" + resp.Status
		return nil, errors.New(errMsg)
	}

	var deviceAuth DeviceAuth
	err = json.NewDecoder(resp.Body).Decode(&deviceAuth)

	if err != nil {
		return nil, err
	}
	return &deviceAuth, nil
}

func RequestToken(tenant string, clientId string, deviceAuth *DeviceAuth) (*AuthenticationResult, error) {
	resp, err := http.PostForm("https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token",
		url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {clientId}, "device_code": {deviceAuth.DeviceCode}})

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusBadRequest {
			var authErr AuthenticationError
			err = json.NewDecoder(resp.Body).Decode(&authErr)
			if err != nil {
				return nil, err
			}

			if authErr.Type == PENDING {
				return nil, nil
			} else if authErr.Type != "" {
				return nil, errors.New("Polling of device_code concluded with " + authErr.Type)
			}
		}

		errMsg := "Request failed with status code:" + resp.Status
		return nil, errors.New(errMsg)
	}

	var authResult AuthenticationResult
	err = json.NewDecoder(resp.Body).Decode(&authResult)

	if err != nil {
		return nil, err
	}

	return &authResult, nil
}

type FederatedAuthData struct {
	RedirectUrl string
	SAMLRequest string
	RelayState  string
}

func EnterDeviceCodeWithHeadlessBrowser(userCode string, tenantInfo *TenantInfo, userAgent string) (*FederatedAuthData, error) {
	allocatorOpts := chromedp.DefaultExecAllocatorOptions[:]
	allocatorOpts = append(allocatorOpts, chromedp.Flag("headless", true))
	allocatorOpts = append(allocatorOpts, chromedp.UserAgent(userAgent))
	ctx, cancel := chromedp.NewExecAllocator(context.Background(), allocatorOpts...)

	var contextOpts []chromedp.ContextOption
	contextOpts = append(contextOpts, chromedp.WithDebugf(slog.Debug))
	ctx, cancel = chromedp.NewContext(ctx, contextOpts...)

	defer cancel()

	// Inject JS to intercept form submissions before they fire.
	// Microsoft's login page auto-submits a hidden form with SAMLRequest
	// and RelayState via POST. We capture that data before it leaves.
	interceptJS := `
	(function() {
		window.__samlIntercepted = null;
		var origSubmit = HTMLFormElement.prototype.submit;
		HTMLFormElement.prototype.submit = function() {
			var data = {};
			var inputs = this.querySelectorAll('input');
			for (var i = 0; i < inputs.length; i++) {
				data[inputs[i].name] = inputs[i].value;
			}
			data['__action'] = this.action;
			window.__samlIntercepted = JSON.stringify(data);
			// Don't actually submit - we've captured what we need
		};
	})();
	`

	err := chromedp.Run(ctx,
		chromedp.Navigate(`https://microsoft.com/devicelogin`),

		chromedp.WaitVisible(`#idSIButton9`),
		chromedp.SendKeys(`#otc`, userCode),
		chromedp.Click(`#idSIButton9`),

		chromedp.WaitVisible(`//input[@name="loginfmt"]`, chromedp.BySearch),
		chromedp.WaitVisible(`//input[@type="submit"]`, chromedp.BySearch),

		// Inject the form interceptor before submitting the UPN
		chromedp.Evaluate(interceptJS, nil),

		chromedp.SendKeys(`//input[@name="loginfmt"]`, tenantInfo.ExampleUpn, chromedp.BySearch),
		chromedp.Click(`//input[@type="submit"]`, chromedp.BySearch),
	)

	if err != nil {
		return nil, err
	}

	// Poll for intercepted form data
	waitTimeIntervalMs := 100
	waitTimeMaxMs := 30000
	waitTimeCurrentMs := 0

	for waitTimeCurrentMs <= waitTimeMaxMs {
		time.Sleep(time.Duration(waitTimeIntervalMs) * time.Millisecond)
		waitTimeCurrentMs = waitTimeCurrentMs + waitTimeIntervalMs

		var intercepted string
		err = chromedp.Run(ctx,
			chromedp.Evaluate(`window.__samlIntercepted || ""`, &intercepted),
		)

		if err != nil {
			return nil, err
		}

		if intercepted == "" {
			continue
		}

		// Parse the intercepted form data
		var formData map[string]string
		err = json.Unmarshal([]byte(intercepted), &formData)
		if err != nil {
			return nil, err
		}

		action := formData["__action"]
		actionParsed, err := url.Parse(action)
		if err != nil {
			return nil, err
		}

		if !strings.EqualFold(actionParsed.Host, tenantInfo.UserRealmInfo.getFederatedAuthURLHost()) {
			slog.Info("Intercepted form POST to non-federated host: " + action + ", continuing...")
			// Reset and keep waiting
			chromedp.Run(ctx, chromedp.Evaluate(`window.__samlIntercepted = null`, nil))
			continue
		}

		samlRequest := formData["SAMLRequest"]
		relayState := formData["RelayState"]

		slog.Info("Intercepted SAML POST form", "SAMLRequestLen", len(samlRequest), "RelayStateLen", len(relayState))

		return &FederatedAuthData{
			RedirectUrl: action,
			SAMLRequest: samlRequest,
			RelayState:  relayState,
		}, nil
	}

	return nil, errors.New("No SAML form submission to FederatedAuthURL " + tenantInfo.UserRealmInfo.getFederatedAuthURLHost() + " intercepted")
}
