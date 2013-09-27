package minnow

import (
	"fmt"
	"io"
)

func ExampleWriteCloser() {
	secret := []byte("toomanysecrets")
	message := []byte("Anybody want to shutdown the Federal Reserve?")
	r, w := io.Pipe()

	// Create the Writer and Reader "connections"
	wconn := NewWriteCloser(secret, w)
	rconn := NewReader(secret, r)

	// Actually write the message
	wconn.Write(message)

	// Nothing is actually written until Close is called
	// (When writing to a pipe, Close blocks until the data is read,
	// so execute in a goroutine)
	go wconn.Close()

	fmt.Printf("%s\n", rconn.ReadAll())
	// Output: Anybody want to shutdown the Federal Reserve?
}
