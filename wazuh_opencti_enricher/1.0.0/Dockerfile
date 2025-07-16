# Base our app image off of the Shuffle App SDK image
FROM frikky/shuffle:app_sdk as base

# Builder stage to install Python dependencies
FROM base as builder

# Install Alpine build tools needed for pip installs that might compile C extensions
# pycti'nin ihtiyacı olup olmadığını kontrol etmekte fayda var, ama standart olarak ekliyoruz
RUN apk --no-cache add --update alpine-sdk libffi libffi-dev musl-dev openssl-dev

# Install all of our pip packages in a single directory for copying
RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN pip install --prefix="/install" -r /requirements.txt

# Final image stage
FROM base
COPY --from=builder /install /usr/local
COPY src /app 
# src klasörü app klasörünün içinde kalacak

# No specific binary dependencies needed for pycti based on typical usage.
# If you encounter issues later, consider adding them here, e.g.:
# RUN apk --no-cache add --update some_binary_dependency

# Run the app
WORKDIR /app
CMD python src/app.py --log-level DEBUG # src klasörü içinde olduğu için src/app.py
