package authentication

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtKey = "secret_key"

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func AuthMiddleware() gin.HandlerFunc {
	var jwtKeyByte = []byte(jwtKey)
	return func(ctx *gin.Context) {
		tokenString := ctx.GetHeader("Authorization")

		if tokenString == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			ctx.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
			return jwtKeyByte, nil
		})
		if !token.Valid || err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			ctx.Abort()
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		ctx.Set("claims", claims)

		ctx.Next()
	}
}

func loginHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error:": err.Error()})
		return
	}

	//logic authentication
	if user.Username == "enigma" && user.Password == "12345" {
		// bikin code untuk generate token
		token := jwt.New(jwt.SigningMethodHS256)

		claims := token.Claims.(jwt.MapClaims)

		claims["username"] = user.Username
		claims["exp"] = time.Now().Add(time.Minute * 1).Unix()

		var jwtKeyByte = []byte(jwtKey)
		tokenString, err := token.SignedString(jwtKeyByte)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
	}
}

func profileHandler(c *gin.Context) {
	// ambil username dari jwt token
	claims := c.MustGet("claims").(jwt.MapClaims)
	username := claims["username"].(string)

	//seharusnya return user dari database, tapi dari contoh ini kita return username
	c.JSON(http.StatusOK, gin.H{"username ": username})
}
