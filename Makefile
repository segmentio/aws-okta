version := $$CIRCLE_TAG

release: gh-release clean dist
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
	--name aws-okta-$(version)-darwin-amd64 \
	--file dist/aws-okta-$(version)-darwin-amd64

	github-release upload \
	--security-token $$GH_LOGIN \
	--user segmentio \
	--repo aws-okta \
	--tag $(version) \
	--name aws-okta-$(version)-linux-amd64 \
	--file dist/aws-okta-$(version)-linux-amd64

clean:
	rm -rf ./dist

dist:
	mkdir dist
	GOOS=darwin GOARCH=amd64 go build -o dist/aws-okta-$(version)-darwin-amd64
	GOOS=linux GOARCH=amd64 go build -o dist/aws-okta-$(version)-linux-amd64

gh-release:
	go get -u github.com/aktau/github-release
