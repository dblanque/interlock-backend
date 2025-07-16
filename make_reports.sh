#!/bin/bash

source . venv/bin/activate
pytest	--cov \
		--cov-report xml:reports/coverage/coverage.xml \
		--cov-report html:reports/coverage/html \
		--junitxml=reports/junit/junit.xml
coverage report -m
genbadge tests
genbadge coverage
