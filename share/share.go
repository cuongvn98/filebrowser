package share

import (
	"math/rand"
	"time"
)

// Link is the information needed to build a shareable link.
type Link struct {
	Hash   string `json:"hash" storm:"id,index"`
	Path   string `json:"path" storm:"index"`
	UserID uint   `json:"userID"`
	Expire int64  `json:"expire"`
}

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func RandomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandomString(length int) string {
	return RandomStringWithCharset(length, charset)
}
