package joke

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"project1/internal/config"
)

type joke struct {
	ID        uint   `json:"id"`
	Type      string `json:"type"`
	Setup     string `json:"setup"`
	Punchline string `json:"punchline"`
}

func Jokes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}

	url := config.GetUrl()

	result, err := parseJoke(url)

	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("\n the joke is  = %s", result.Punchline)
}

func parseJoke(url string) (joke, error) {
	req, err := http.NewRequest("GET", url, nil)

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		fmt.Println(err)
	}

	var result joke

	err = json.Unmarshal(body, &result)

	return joke{
		ID:        result.ID,
		Type:      result.Type,
		Setup:     result.Setup,
		Punchline: result.Punchline,
	}, err
}
