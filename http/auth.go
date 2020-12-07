package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"

	"github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/share"
	"github.com/filebrowser/filebrowser/v2/users"
)

const (
	TokenExpirationTime = time.Hour * 24 * 365
)

type userInfo struct {
	ID           uint              `json:"id"`
	Locale       string            `json:"locale"`
	ViewMode     users.ViewMode    `json:"viewMode"`
	SingleClick  bool              `json:"singleClick"`
	Perm         users.Permissions `json:"perm"`
	Commands     []string          `json:"commands"`
	LockPassword bool              `json:"lockPassword"`
	HideDotfiles bool              `json:"hideDotfiles"`
}

type authToken struct {
	User userInfo `json:"user"`
	jwt.StandardClaims
}

type extractor []string

func (e extractor) ExtractToken(r *http.Request) (string, error) {
	token, _ := request.HeaderExtractor{"X-Auth"}.ExtractToken(r)

	// Checks if the token isn't empty and if it contains two dots.
	// The former prevents incompatibility with URLs that previously
	// used basic auth.
	if token != "" && strings.Count(token, ".") == 2 {
		return token, nil
	}

	auth := r.URL.Query().Get("auth")
	if auth == "" {
		return "", request.ErrNoTokenInRequest
	}

	return auth, nil
}

func withUser(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			return d.settings.Key, nil
		}

		var tk authToken
		token, err := request.ParseFromRequest(r, &extractor{}, keyFunc, request.WithClaims(&tk))

		if err != nil || !token.Valid {
			return http.StatusForbidden, nil
		}

		expired := !tk.VerifyExpiresAt(time.Now().Add(time.Hour).Unix(), true)
		updated := d.store.Users.LastUpdate(tk.User.ID) > tk.IssuedAt

		if expired || updated {
			w.Header().Add("X-Renew-Token", "true")
		}

		d.user, err = d.store.Users.Get(d.server.Root, tk.User.ID)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		return fn(w, r, d)
	}
}

func withAdmin(fn handleFunc) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if !d.user.Perm.Admin {
			return http.StatusForbidden, nil
		}

		return fn(w, r, d)
	})
}

var loginHandler = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	auther, err := d.store.Auth.Get(d.settings.AuthMethod)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	user, err := auther.Auth(r, d.store.Users, d.server.Root)
	if err == os.ErrPermission {
		return http.StatusForbidden, nil
	} else if err != nil {
		return http.StatusInternalServerError, err
	} else {
		return printToken(w, r, d, user)
	}
}

var loginWithINETHandler = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	var extractor sidExtractor
	ue, err := extractor.ExtractToken(r)

	if !strings.HasSuffix(ue.Email, "@inet.vn") {
		return http.StatusForbidden, fmt.Errorf("you are not allowed to sign in with %s", ue.Email)
	}
	if err != nil {
		return http.StatusBadRequest, err
	}
	user, err := d.store.Users.Get(d.server.Root, ue.Email)
	if err != nil && err.Error() != "the resource does not exist" {
		return http.StatusInternalServerError, err
	}
	if user == nil {
		user = &users.User{
			Username: ue.Email,
		}
		d.settings.Defaults.Apply(user)
		user.Perm = users.Permissions{
			Admin:    false,
			Execute:  false,
			Create:   false,
			Rename:   false,
			Modify:   false,
			Delete:   false,
			Share:    false,
			Download: true,
		}
		var passwordLength = 10
		user.Password = share.RandomString(passwordLength)

		userHome, err := d.settings.MakeUserDir(user.Username, user.Scope, d.server.Root)
		if err != nil {
			log.Printf("create user: failed to mkdir user home dir: [%s]", userHome)
			return http.StatusInternalServerError, err
		}
		user.Scope = userHome
		log.Printf("new user: %s, home dir: [%s].", user.Username, userHome)

		err = d.store.Users.Save(user)
		if err == errors.ErrExist {
			return http.StatusConflict, err
		} else if err != nil {
			return http.StatusInternalServerError, err
		}
	}
	return printToken(w, r, d, user)
}

type sidExtractor struct{}

var (
	tr = &http.Transport{
		MaxIdleConns:    20,
		IdleConnTimeout: 30 * time.Second,
	}
	client = &http.Client{Transport: tr}
)

func (e *sidExtractor) ExtractToken(r *http.Request) (userExchange, error) {
	c, err := r.Cookie("sid")
	var user userExchange
	if err != nil {
		return user, err
	}
	if c.Value == "" {
		return user, errors.ErrEmptyKey
	}

	return e.exchange(c.Value)
}

func (e *sidExtractor) exchange(sid string) (userExchange, error) {
	user := userExchange{}
	body := e.sidToBody(sid)
	resp, err := client.Post("https://sso.inet.vn/api/admin/v1/account/verifysid", "application/json", body)
	if err != nil {
		return user, err
	}
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()
	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		return user, err
	}
	if user.Email == "" {
		return user, errors.ErrEmptyUsername
	}
	return user, nil
}

func (e *sidExtractor) sidToBody(sid string) io.Reader {
	b, _ := json.Marshal(map[string]string{
		"sid": sid,
	})
	return bytes.NewBuffer(b)
}

type userExchange struct {
	Email    string `json:"email"`
	FullName string `json:"fullname"`
	Phone    string `json:"phone"`
	Avatar   string `json:"avatar"`
	Reseller bool   `json:"reseller"`
}

type signupBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var signupHandler = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if !d.settings.Signup {
		return http.StatusMethodNotAllowed, nil
	}

	if r.Body == nil {
		return http.StatusBadRequest, nil
	}

	info := &signupBody{}
	err := json.NewDecoder(r.Body).Decode(info)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if info.Password == "" || info.Username == "" {
		return http.StatusBadRequest, nil
	}

	user := &users.User{
		Username: info.Username,
	}

	d.settings.Defaults.Apply(user)

	pwd, err := users.HashPwd(info.Password)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	user.Password = pwd

	userHome, err := d.settings.MakeUserDir(user.Username, user.Scope, d.server.Root)
	if err != nil {
		log.Printf("create user: failed to mkdir user home dir: [%s]", userHome)
		return http.StatusInternalServerError, err
	}
	user.Scope = userHome
	log.Printf("new user: %s, home dir: [%s].", user.Username, userHome)

	err = d.store.Users.Save(user)
	if err == errors.ErrExist {
		return http.StatusConflict, err
	} else if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

var renewHandler = withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	return printToken(w, r, d, d.user)
})

func printToken(w http.ResponseWriter, _ *http.Request, d *data, user *users.User) (int, error) {
	claims := &authToken{
		User: userInfo{
			ID:           user.ID,
			Locale:       user.Locale,
			ViewMode:     user.ViewMode,
			SingleClick:  user.SingleClick,
			Perm:         user.Perm,
			LockPassword: user.LockPassword,
			Commands:     user.Commands,
			HideDotfiles: user.HideDotfiles,
		},
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(TokenExpirationTime).Unix(),
			Issuer:    "File Browser",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(d.settings.Key)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte(signed)); err != nil {
		return http.StatusInternalServerError, err
	}
	return 0, nil
}
