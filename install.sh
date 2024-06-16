#!/bin/bash

# Download Go package
echo "Downloading Go..."
curl -O https://dl.google.com/go/go1.21.linux-amd64.tar.gz

# Install Go
echo "Installing Go..."
tar -xvf go1.21.linux-amd64.tar.gz
sudo chown -R root:root ./go
sudo mv go /usr/local

# Set Go environment variables
echo "Setting Go environment variables..."
echo "export GOPATH=$HOME/go" >> ~/.profile
echo "export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin" >> ~/.profile
source ~/.profile

# Install Go tools
echo "Installing Go tools..."
go get -u github.com/golang/protobuf/protoc-gen-go
go get -u golang.org/x/lint/golint
go get -u golang.org/x/tools/cmd/godoc
go get -u golang.org/x/tools/cmd/goimports
go get -u golang.org/x/tools/cmd/gorename
go get -u golang.org/x/tools/cmd/guru
go get -u github.com/cweill/gotests/...
go install -v github.com/projectdiscovery/wappalyzergo/cmd/update-fingerprints@latest

echo "Installation complete!"
https://github.com/blackhatethicalhacking/Nucleimonst3r
#installs most go tools used.
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/lc/gau/v2/cmd/gau@latest
echo "Done with most go tools, just a bit more left! \n\n"

git clone https://github.com/blackhatethicalhacking/Nucleimonst3r
cd Nucleimonst3r/
chmod +x Nucleimonst3r.sh
