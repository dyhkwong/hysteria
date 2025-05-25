package server

import (
	"io"
)

func copyTwoWay(serverRw, remoteRw io.ReadWriter) error {
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(serverRw, remoteRw)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(remoteRw, serverRw)
		errChan <- err
	}()
	// Block until one of the two goroutines returns
	return <-errChan
}
