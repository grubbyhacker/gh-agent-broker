package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"gh-agent-broker/internal/repositorybackend"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8081", "listen address")
	repository := flag.String("repository", "/var/lib/repository-backend/repository-agent-lifecycle-fixture.git", "absolute bare repository path")
	name := flag.String("repository-name", "repository-agent-lifecycle-fixture", "fixed repository name")
	flag.Parse()
	h, err := repositorybackend.New(repositorybackend.Config{RepositoryPath: *repository, RepositoryName: *name, ExpectedUID: os.Getuid(), ExpectedGID: os.Getgid(), RepositoryMode: 0o755})
	if err != nil {
		log.Fatal(err)
	}
	s := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute}
	log.Fatal(s.ListenAndServe())
}
