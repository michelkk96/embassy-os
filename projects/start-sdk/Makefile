TS_FILES := $(shell git ls-files lib)
START_CORE := ../../shared-libs/ts-modules/start-core
START_CORE_DIST := $(START_CORE)/dist
START_CORE_SRC := $(shell git ls-files $(START_CORE)/lib) $(START_CORE)/package.json

.PHONY: all test clean clean-dist bundle fmt check-fmt check publish link node_modules

all: bundle

# start-core is an external dependency now: the SDK imports it and bundles its
# built lib into the published dist so external authors still install one package.
# Prerequisites matter here: with none, this only fired when start-core/dist was
# *missing*, leaving the SDK's dist stale against a rebuilt start-core.
$(START_CORE_DIST)/package.json: $(START_CORE_SRC)
	$(MAKE) -C $(START_CORE) dist

test: node_modules
	npm test

clean:
	rm -rf dist node_modules lib/test/output.ts

clean-dist:
	rm -rf dist

# Build artifacts only — verification (test/check-fmt) is intentionally NOT a
# prerequisite so consumers (the OS build) don't re-run the jest suite every
# build. CI and `publish` run test/check-fmt explicitly.
bundle: dist
	touch dist

dist: $(TS_FILES) package.json .npmignore node_modules README.md LICENSE CHANGELOG.md s9pk.mk tsconfig.base.json eslint.config.base.mjs lint.mjs $(START_CORE_DIST)/package.json
	rm -rf dist
	npm run tsc
	rsync -ac node_modules dist/
	rm -rf dist/node_modules/@start9labs/start-core
	mkdir -p dist/node_modules/@start9labs
	rsync -aL $(START_CORE_DIST)/ dist/node_modules/@start9labs/start-core/
	# The hidden lockfile rsync'd in above records start-core as a `file:` link out to
	# shared-libs, so `npm publish` resolves the bundled dep through it and emits paths
	# outside the package root (npm E415) despite the real files being right here.
	rm -f dist/node_modules/.package-lock.json
	cp package.json dist/package.json
	cp .npmignore dist/.npmignore
	cp README.md dist/README.md
	cp LICENSE dist/LICENSE
	cp CHANGELOG.md dist/CHANGELOG.md
	cp s9pk.mk dist/s9pk.mk
	cp tsconfig.base.json dist/tsconfig.base.json
	cp eslint.config.base.mjs dist/eslint.config.base.mjs
	cp lint.mjs dist/lint.mjs
	touch dist

full-bundle: bundle

check: node_modules
	npm run check

fmt: node_modules
	npx prettier "**/*.ts" --write

check-fmt: node_modules
	npx prettier "**/*.ts" --check

package-lock.json: package.json $(START_CORE_DIST)/package.json
	npm i

node_modules: package-lock.json $(START_CORE_DIST)/package.json
	npm ci

# Rebuild dist from scratch: it is a directory target, so make's staleness check
# does not track its contents, and a stale dist packed 2.0.5 as 2.0.4.
# Prompt for the npm 2FA OTP here (after the build) so it can't expire; OTP=… skips.
publish: test check-fmt package.json README.md LICENSE CHANGELOG.md
	$(MAKE) clean-dist
	$(MAKE) bundle
	@otp='$(OTP)'; \
	if [ -z "$$otp" ] && [ -t 0 ]; then \
		printf 'npm one-time password (OTP): ' >&2; \
		read -r otp; \
	fi; \
	cd dist && npm publish --access=public --tag=latest $${otp:+--otp=$$otp}

link: bundle
	cd dist && npm link
