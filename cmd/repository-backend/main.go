package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"gh-agent-broker/internal/repositorybackend"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8081", "listen address")
	repository := flag.String("repository", "/var/lib/repository-backend/repository-proof.git", "absolute bare repository path")
	name := flag.String("repository-name", "repository-proof", "fixed repository name")
	flag.Parse()
	h, err := repositorybackend.New(repositorybackend.Config{RepositoryPath: *repository, RepositoryName: *name})
	if err != nil {
		log.Fatal(err)
	}
	s := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute}
	log.Fatal(s.ListenAndServe())
}
