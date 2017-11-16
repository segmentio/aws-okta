version := $$CIRCLE_TAG

release: gh-release govendor clean dist
	github-release release \
	--security-token $$GH_LOGIN \
	--user segmentio \
	--repo aws-okta \
	--tag $(version) \
	--name $(version)

	github-release upload \
	--security-token $$GH_LOGIN \
	--user segmentio \
	--repo aws-okta \
	--tag $(version) \
	--name aws-okta-$(version)-linux-amd64 \
	--file dist/aws-okta-$(version)-linux-amd64

release-mac: gh-release govendor clean dist-mac
	github-release upload \
	--security-token $$GH_LOGIN \
	--user segmentio \
	--repo aws-okta \
	--tag $(version) \
	--name aws-okta-$(version)-darwin-amd64 \
	--file dist/aws-okta-$(version)-darwin-amd64

clean:
	rm -rf ./dist

dist:
	mkdir dist
	govendor sync
	GOOS=linux GOARCH=amd64 go build -o dist/aws-okta-$(version)-linux-amd64

dist-mac:
	mkdir dist
	govendor sync
	GOOS=darwin GOARCH=amd64 go build -o dist/aws-okta-$(version)-darwin-amd64

gh-release:
	go get -u github.com/aktau/github-release

govendor:
	go get -u github.com/kardianos/govendor
