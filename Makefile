# build create virtual environment and install dependencies
build:
	python3 -m venv venv
	. venv/bin/activate && \
		pip install -r requirements.txt

# run program with given type and port
run:
	. venv/bin/activate && \
		python3 kry.py TYPE=$(TYPE) PORT=$(PORT)