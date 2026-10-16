package handler

import (
	"errors"
	"fmt"
	"log"
)

// Process handles a single item by id.
func Process(id string) error {
	_, _ = doThing(id)
	return nil
}

// ProcessLogged handles a single item and reports failures.
func ProcessLogged(id string) error {
	result, err := doThing(id)
	if err != nil {
		log.Printf("process %s failed: %v", id, err)
		return err
	}
	return save(result)
}

func doThing(id string) (string, error) {
	if id == "" {
		return "", errors.New("empty id")
	}
	return fmt.Sprintf("thing-%s", id), nil
}

func save(result string) error {
	if result == "" {
		return errors.New("empty result")
	}
	return nil
}
