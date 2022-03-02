help: Makefile
	@echo
	@echo " Available commands: "
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

## go-encrypt: encrypt plaintext using golang snippet
go-encrypt: 
	cd go && go run . -action=encrypt

## go-decrypt: decrypt encrypted text using golang snippet
go-decrypt: 
	cd go && go run . -action=decrypt
