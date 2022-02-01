FROM mcr.microsoft.com/vscode/devcontainers/python:0-3.8

WORKDIR /workspaces

# Install Python dependencies from requirements.txt if it exists
COPY requirements_test.txt .
RUN pip3 install -r requirements_test.txt \
    && pip3 install tox \
    && rm -f requirements_test.txt

# Set the default shell to bash instead of sh
ENV SHELL /bin/bash
