package robot

import (
	"io/ioutil"
	"net/http"
	"strings"
)

func PostHeader(url string, msg []byte, headers map[string]string) (string, error) {
	client := &http.Client{}

	req, err := http.NewRequest("POST", url, strings.NewReader(string(msg)))
	if err != nil {
		return "", err
	}
	for key, header := range headers {
		req.Header.Set(key, header)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func PostJson(url string, msg []byte) (string, error) {
	headers := make(map[string]string)
	headers["Content-Type"] = "application/json;charset=utf-8"
	res, err := PostHeader(url, msg, headers)
	return res, err
}
