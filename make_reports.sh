#!/bin/bash

source ./venv/bin/activate || exit 1

dirs=(
	"reports/coverage/html"
	"reports/junit"
	"reports/badges"
)
# Ensure required directories exist
for d in "${dirs[@]}"; do
	if [ ! -d "$d"]; then
		mkdir -p "$d" || exit 2
	fi
done

# Prune old HTML Reports
html_reports_dir="reports/coverage/html"
if [ -d "$html_reports_dir" ]; then
	rm -rf "$html_reports_dir"
fi

pytest	--cov \
		--cov-report "xml:reports/coverage/coverage.xml" \
		--cov-report "html:$html_reports_dir" \
		--junitxml=reports/junit/junit.xml

# Print coverage to console.
coverage report -m

# Make badges
echo "Generating badges..."
{
	genbadge tests && genbadge coverage;
	mv *".svg" "reports/badges/";
	python3 generate_custom_badges.py
} || echo "Finished report generation with errors."
