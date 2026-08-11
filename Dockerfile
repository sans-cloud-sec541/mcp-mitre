FROM python:3.11-slim

WORKDIR /app

# Install uv
RUN pip install --upgrade pip && pip install uv

# Copy project files
COPY main.py .
COPY attack_data_wrapper.py .
COPY ATLAS.yaml .
COPY MORIARTY.yaml .
COPY enterprise-attack.json .
COPY pyproject.toml .
COPY uv.lock .

# Sync/install dependencies using uv (it creates venv in .venv automatically)
RUN uv sync

# No need to modify the STIX data anymore, our custom wrapper handles it

# Run the MCP server using uv
CMD ["uv", "run", "main.py", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8099"]
